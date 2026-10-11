//! Application-owned HTTP graph and direct upload/download localsides.
use hibana::runtime::program::Projectable;
use hibana::{
    Endpoint,
    g::{self, Message},
};
use hibana_quic::http3::{
    localside::client::{DOWNLOAD, READ, UPLOAD, WRITE},
    message::{self, Exchange, FieldSection, global::*},
};
use std::io::Write;

/// The writer transfers the actual request method before response decoding.
pub fn choreography() -> impl Projectable {
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

pub async fn upload(
    upload: &mut Endpoint<'_, UPLOAD>,
    request: &Exchange<'_>,
) -> message::Result<()> {
    let method = std::env::var("HTTP_METHOD").unwrap_or_else(|_| "POST".into());
    let path = std::env::var("HTTP_PATH")
        .unwrap_or_else(|_| if method == "POST" { "/echo" } else { "/hello" }.into());
    let body = std::env::var("HTTP_BODY").unwrap_or_else(|_| {
        if method == "POST" {
            "hello from Hibana\n"
        } else {
            ""
        }
        .into()
    });
    let length = body.len().to_string();
    request.request(
        method.as_bytes(),
        b"localhost",
        path.as_bytes(),
        &[
            (b"content-type", b"application/octet-stream"),
            (b"content-length", length.as_bytes()),
        ],
    )?;
    upload.send::<Headers>(&()).await?;
    upload.recv::<Stored>().await?;

    // Each storage write prepares only one bounded DATA payload. The actual
    // endpoint publishes it and waits for reuse before the next write.
    for chunk in body.as_bytes().chunks(1024) {
        let mut remaining = chunk;
        while !remaining.is_empty() {
            let count = request.write(remaining)?;
            upload.send::<Data>(&count).await?;
            upload.recv::<Stored>().await?;
            remaining = &remaining[usize::try_from(count)?..];
        }
    }
    upload.send::<BodyEnd>(&()).await?;
    upload.send::<NoTrailers>(&()).await?;
    upload.send::<End>(&()).await?;
    upload.recv::<Done>().await?;
    Ok(())
}

pub async fn download(
    download: &mut Endpoint<'_, DOWNLOAD>,
    response: &Exchange<'_>,
) -> message::Result<()> {
    download.recv::<RequestMethod>().await?;

    loop {
        let offered = download.offer().await?;
        let final_headers = match offered.label() {
            Information::LOGICAL_LABEL => {
                offered.recv::<Information>().await?;
                false
            }
            Headers::LOGICAL_LABEL => {
                offered.recv::<Headers>().await?;
                true
            }
            _ => return Err("unexpected response header branch".into()),
        };
        let fields = response.fields()?;
        let section = fields.section();
        eprintln!(
            "HTTP/3 {}",
            section.metadata.status.ok_or("missing status")?
        );
        print_fields(section)?;
        drop(fields);
        download.send::<Stored>(&()).await?;
        if final_headers {
            break;
        }
    }

    let mut length = 0_u64;
    loop {
        let offered = download.offer().await?;
        match offered.label() {
            Data::LOGICAL_LABEL => {
                let count = offered.recv::<Data>().await?;
                let body = response.body(count)?;
                std::io::stdout()
                    .write_all(body.bytes())
                    .map_err(|_| "stdout failed")?;
                length = length
                    .checked_add(count)
                    .ok_or("response length overflow")?;
                drop(body);
                download.send::<Stored>(&()).await?;
            }
            BodyEnd::LOGICAL_LABEL => {
                offered.recv::<BodyEnd>().await?;
                break;
            }
            _ => return Err("unexpected response body branch".into()),
        }
    }
    let offered = download.offer().await?;
    match offered.label() {
        Trailers::LOGICAL_LABEL => {
            offered.recv::<Trailers>().await?;
            let fields = response.fields()?;
            print_fields(fields.section())?;
            drop(fields);
            download.send::<Stored>(&()).await?;
        }
        NoTrailers::LOGICAL_LABEL => {
            offered.recv::<NoTrailers>().await?;
        }
        _ => return Err("unexpected response trailer branch".into()),
    }
    download.recv::<End>().await?;
    std::io::stdout().flush().map_err(|_| "stdout failed")?;
    download.send::<Done>(&()).await?;
    eprintln!("{length} response bytes");
    Ok(())
}

// Formatting only: this helper cannot advance a protocol endpoint.
fn print_fields(section: FieldSection<'_>) -> message::Result<()> {
    section.for_each(|name, value| {
        if !name.starts_with(b":") {
            eprintln!(
                "{}: {}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(value)
            );
        }
        Ok(())
    })
}
