//! Application global and localside; native initialization is in ../environment.rs.
#[path = "../environment.rs"]
mod environment;
mod global;
use global::{Number, Square};
use hibana::runtime::program::project;
use hibana_quic::session::Protocol;
fn main() -> Result<(), String> {
    environment::client(Protocol::default(), async |client| {
        client
            .run(
                project::<{ global::CLIENT }>(&global::choreography()),
                async |client| -> Result<(), ApplicationError> {
                    for number in [42_u64, 7] {
                        client
                            .send::<Number>(&number)
                            .await
                            .map_err(ApplicationError::Protocol)?;
                        let square = client
                            .recv::<Square>()
                            .await
                            .map_err(ApplicationError::Protocol)?;
                        if square != number * number {
                            return Err(ApplicationError::IncorrectSquare);
                        }
                    }
                    Ok(())
                },
            )
            .await
    })?;
    println!("42 squared = 1764\n7 squared = 49");
    Ok(())
}

#[derive(Debug)]
pub enum ApplicationError {
    Protocol(hibana::EndpointError),
    IncorrectSquare,
}
