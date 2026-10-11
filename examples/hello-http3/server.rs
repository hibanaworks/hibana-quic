//! Ordinary HTTP/3: GET/HEAD /hello, streaming POST /echo, and 404.
//! Native credentials, sockets and execution stay in ../environment.rs.
#[path = "../environment.rs"]
mod environment;
mod server_app;

use hibana_quic::{http3::Storage, session::Protocol};

fn main() -> Result<(), String> {
    let global = server_app::choreography();
    let mut storage = const { Storage::<4096>::new() };
    environment::server(Protocol::Http3, async |server| {
        server.http3(&global, &mut storage, server_app::serve).await
    })?;
    println!("served HTTP/3 request");
    Ok(())
}
