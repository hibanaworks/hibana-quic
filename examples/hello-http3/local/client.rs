use crate::global::*;
use hibana::Endpoint;
#[derive(Debug)]
pub enum Error {
    Protocol(hibana::EndpointError),
    IncorrectSquare,
}
pub async fn run(client: &mut Endpoint<'_, CLIENT>) -> Result<(), Error> {
    for number in [42_u64, 7] {
        client
            .send::<Number>(&number)
            .await
            .map_err(Error::Protocol)?;
        let square = client.recv::<Square>().await.map_err(Error::Protocol)?;
        if square != number * number {
            return Err(Error::IncorrectSquare);
        }
    }
    Ok(())
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "{error:?}"),
            Self::IncorrectSquare => f.write_str("incorrect square"),
        }
    }
}
impl core::error::Error for Error {}
