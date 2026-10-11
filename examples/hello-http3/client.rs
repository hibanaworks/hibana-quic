//! A native HTTP/3 request with independent upload and response localsides.
#[path = "../environment.rs"]
mod environment;
use hibana_quic::{
    http3::{
        Storage,
        localside::client::{DOWNLOAD, READ, UPLOAD, WRITE},
        message::{self, Consumer, FieldSection},
    },
    session::Protocol,
};

struct Print;
impl Consumer for Print {
    async fn headers(&mut self, fields: FieldSection<'_>) -> message::Result<()> {
        println!("HTTP/3 {}", fields.metadata.status.ok_or("missing status")?);
        Ok(())
    }
    async fn data(&mut self, _: u64, bytes: &[u8]) -> message::Result<()> {
        use std::io::Write;
        std::io::stdout()
            .write_all(bytes)
            .map_err(|_| "stdout failed")?;
        Ok(())
    }
    async fn complete(&mut self, length: u64) -> message::Result<()> {
        println!("\n{length} response bytes");
        Ok(())
    }
}

fn main() -> Result<(), String> {
    environment::client(Protocol::Http3, async |client| {
        let global = message::global::client::<UPLOAD, WRITE, READ, DOWNLOAD>();
        let mut storage = const { Storage::<4096>::new() };
        client
            .http3(
                &global,
                &mut storage,
                async |upload, mut request| {
                    request
                        .headers(upload, b"POST", b"localhost", b"/echo", &[])
                        .await?;
                    request.write(upload, b"hello from Hibana").await?;
                    request.finish(upload).await
                },
                async |download, response| {
                    response.receive(download, &mut Print).await?;
                    Ok(())
                },
            )
            .await
    })
}
