//! Application global and localside; native initialization is in ../environment.rs.
// Project the complete TLS/QUIC/application graph in this binary.
#[path = "../environment.rs"]
mod environment;
mod global;
use global::{Number, Square};
use hibana::runtime::program::project;
use hibana_quic::session::Protocol;
fn main() -> Result<(), String> {
    environment::server(Protocol::default(), async |server| {
        server
            .run(
                project::<{ global::SERVER }>(&global::choreography()),
                async |server| -> Result<(), ApplicationError> {
                    for _ in 0..2 {
                        let number = server
                            .recv::<Number>()
                            .await
                            .map_err(ApplicationError::Protocol)?;
                        let square = number
                            .checked_mul(number)
                            .ok_or(ApplicationError::Overflow)?;
                        server
                            .send::<Square>(&square)
                            .await
                            .map_err(ApplicationError::Protocol)?;
                    }
                    Ok(())
                },
            )
            .await
    })?;
    println!("served two requests");
    Ok(())
}

#[derive(Debug)]
pub enum ApplicationError {
    Protocol(hibana::EndpointError),
    Overflow,
}
