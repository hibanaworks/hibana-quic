//! Application-owned HTTP graph and direct server localside.
use hibana::runtime::program::Projectable;
use hibana::{
    Endpoint,
    g::{self, Message},
};
use hibana_quic::http3::{
    Method,
    localside::server::{APP, READ, WRITE},
    message::{self, Exchange, global::*},
};

/// The application chooses its HTTP choreography; codecs run READ and WRITE.
pub fn choreography() -> impl Projectable {
    g::seq(
        g::send::<READ, WRITE, RequestMethod>(),
        g::par(request::<READ, APP>(), response::<APP, WRITE>()),
    )
}

pub async fn serve(
    app: &mut Endpoint<'_, APP>,
    request: &Exchange<'_>,
    response: &Exchange<'_>,
) -> message::Result<()> {
    app.recv::<Headers>().await?;
    let fields = request.fields()?;
    let metadata = fields.section().metadata;
    let method = metadata.method.ok_or("missing request method")?;
    let path = &metadata.path[..metadata.path_len];
    let hello = matches!(method, Method::Get | Method::Head) && path == b"/hello";
    let echo = method == Method::Post && path == b"/echo";
    drop(fields);
    // Returning the storage loan and acknowledging reuse are distinct actions.
    app.send::<Stored>(&()).await?;

    if echo {
        response.response(200, &[(b"content-type", b"application/octet-stream")])?;
    } else if hello {
        response.response(
            200,
            &[
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", b"18"),
            ],
        )?;
    } else {
        response.response(
            404,
            &[
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", b"10"),
            ],
        )?;
    }
    app.send::<Headers>(&()).await?;
    app.recv::<Stored>().await?;

    if !echo && method != Method::Head {
        let mut body: &[u8] = if hello {
            b"hello from Hibana\n"
        } else {
            b"not found\n"
        };
        while !body.is_empty() {
            let count = response.write(body)?;
            app.send::<Data>(&count).await?;
            app.recv::<Stored>().await?;
            body = &body[usize::try_from(count)?..];
        }
    }

    // Drain every request. Echo forwards each bounded chunk immediately,
    // retaining its input storage until the response writer has consumed it.
    loop {
        let offered = app.offer().await?;
        match offered.label() {
            Data::LOGICAL_LABEL => {
                let count = offered.recv::<Data>().await?;
                let body = request.body(count)?;
                if echo {
                    let mut remaining = body.bytes();
                    while !remaining.is_empty() {
                        let count = response.write(remaining)?;
                        app.send::<Data>(&count).await?;
                        app.recv::<Stored>().await?;
                        remaining = &remaining[usize::try_from(count)?..];
                    }
                }
                drop(body);
                app.send::<Stored>(&()).await?;
            }
            BodyEnd::LOGICAL_LABEL => {
                offered.recv::<BodyEnd>().await?;
                break;
            }
            _ => return Err("unexpected request body branch".into()),
        }
    }
    let offered = app.offer().await?;
    match offered.label() {
        Trailers::LOGICAL_LABEL => {
            offered.recv::<Trailers>().await?;
            let trailers = request.fields()?;
            // The codec validated these trailing fields; this application
            // consumes them without adding them to its response.
            drop(trailers);
            app.send::<Stored>(&()).await?;
        }
        NoTrailers::LOGICAL_LABEL => {
            offered.recv::<NoTrailers>().await?;
        }
        _ => return Err("unexpected request trailer branch".into()),
    }
    app.recv::<End>().await?;
    app.send::<Done>(&()).await?;

    app.send::<BodyEnd>(&()).await?;
    app.send::<NoTrailers>(&()).await?;
    app.send::<End>(&()).await?;
    app.recv::<Done>().await?;
    Ok(())
}
