//! OS-independent application entry points. Both roles use the same global and
//! connection API as native applications. The board supplies UDP, time, entropy,
//! credentials and caller-owned memory; this is not a boot image or NIC driver.
#![no_std]
#[path = "../../../../examples/hello-quic/global.rs"]
pub mod global;
use global::{Number, Square};
use hibana::runtime::program::project;
use hibana_quic::{
    entropy::Entropy,
    io::{Clock, DatagramSocket},
    session,
};
#[derive(Debug)]
pub enum Error {
    Protocol(hibana::EndpointError),
    IncorrectSquare,
    Overflow,
}
impl From<hibana::EndpointError> for Error {
    fn from(error: hibana::EndpointError) -> Self {
        Self::Protocol(error)
    }
}
pub async fn client<const S: usize, const C: usize, const A: usize>(
    memory: &mut session::Memory<S, C, A>,
    environment: session::Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
    options: session::Client<'_>,
) -> Result<(), session::Error<session::localside::RunError<Error>>> {
    let program = project::<{ global::CLIENT }>(&global::choreography());
    core::pin::pin!(options.run(
        memory,
        environment,
        global::SERVER,
        &program,
        async |client| {
            for number in [42_u64, 7] {
                client.send::<Number>(&number).await?;
                if client.recv::<Square>().await? != number * number {
                    return Err(Error::IncorrectSquare);
                }
            }
            Ok(())
        }
    ))
    .await
}
pub async fn server<const S: usize, const C: usize, const A: usize>(
    memory: &mut session::Memory<S, C, A>,
    environment: session::Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
    options: session::Server<'_>,
) -> Result<(), session::Error<session::localside::RunError<Error>>> {
    let program = project::<{ global::SERVER }>(&global::choreography());
    core::pin::pin!(options.run(
        memory,
        environment,
        global::CLIENT,
        &program,
        async |server| {
            for _ in 0..2 {
                let number = server.recv::<Number>().await?;
                let square = number.checked_mul(number).ok_or(Error::Overflow)?;
                server.send::<Square>(&square).await?;
            }
            Ok(())
        }
    ))
    .await
}

/// Optional HTTP/0.9 file exchange using the same no-OS connection entry points.
#[cfg(feature = "hq")]
pub mod hq;
