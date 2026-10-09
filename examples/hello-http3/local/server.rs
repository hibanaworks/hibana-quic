use crate::global::*;
use hibana::Endpoint;
#[derive(Debug)]
pub enum Error {
    Protocol(hibana::EndpointError),
    Overflow,
}
pub async fn run(server: &mut Endpoint<'_, SERVER>) -> Result<(), Error> {
    for _ in 0..2 {
        let number = server.recv::<Number>().await.map_err(Error::Protocol)?;
        let square = number.checked_mul(number).ok_or(Error::Overflow)?;
        server
            .send::<Square>(&square)
            .await
            .map_err(Error::Protocol)?;
    }
    Ok(())
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "{error:?}"),
            Self::Overflow => f.write_str("square overflow"),
        }
    }
}
impl core::error::Error for Error {}
