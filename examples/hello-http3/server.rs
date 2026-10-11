//! A native HTTP/3 streaming echo application. No application-message tunnel.
#[path = "../environment.rs"]
mod environment;
use hibana_quic::{
    http3::{
        Storage,
        localside::server::{APP, READ, WRITE},
        message,
    },
    session::Protocol,
};

fn main() -> Result<(), String> {
    environment::server(Protocol::Http3, async |server| {
        let global = message::global::server::<READ, APP, WRITE>();
        let mut storage = const { Storage::<4096>::new() };
        server
            .http3(
                &global,
                &mut storage,
                async |app, mut request, mut response| {
                    let headers = request.headers(app).await?;
                    let method = headers.fields().metadata.method;
                    headers.release(app).await?;
                    response
                        .headers(app, 200, &[(b"content-type", b"application/octet-stream")])
                        .await?;
                    while let Some(chunk) = request.chunk(app).await? {
                        if method != Some(hibana_quic::http3::Method::Head) {
                            response.write(app, chunk.bytes()).await?;
                        }
                        chunk.release(app).await?;
                    }
                    request.trailers(app, |_| Ok(())).await?;
                    request.finish(app).await?;
                    response.finish(app).await
                },
            )
            .await
    })?;
    println!("served HTTP/3 echo");
    Ok(())
}
