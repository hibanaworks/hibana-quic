//! A native HTTP/3 client with independent upload and download localsides.
//! Run with the launcher's REMOTE CA.pem arguments. Optional HTTP_METHOD,
//! HTTP_PATH and HTTP_BODY environment variables select the request;
//! defaults are POST /echo with "hello from Hibana\n". HEAD or GET defaults
//! to /hello. Response bytes go to stdout; status and fields go to stderr.
mod client_app;
#[path = "../environment.rs"]
mod environment;

use hibana_quic::{http3::Storage, session::Protocol};

fn main() -> Result<(), String> {
    let global = client_app::choreography();
    let mut storage = const { Storage::<4096>::new() };
    environment::client(Protocol::Http3, async |client| {
        client
            .http3(
                &global,
                &mut storage,
                client_app::upload,
                client_app::download,
            )
            .await
    })
}
