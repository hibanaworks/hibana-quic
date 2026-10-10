//! A single HQ request and a path-to-store server. No filesystem assumptions.
use hibana_quic::{
    entropy::Entropy,
    hq::{Requests, Response, Service},
    io::{Clock, DatagramSocket, RandomAccess},
    quic::application::{Error, Report},
    session::{self, ConnectionMemory, Environment},
};

pub async fn client<const S: usize, const B: usize>(
    memory: &mut ConnectionMemory<S, B>,
    environment: Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
    mut options: session::Client<'_>,
    path: &str,
    output: &impl RandomAccess,
) -> Result<Report, Error> {
    options.protocol = session::Protocol::Hq;
    let paths = [path];
    let mut requests = Requests::new(&paths);
    let mut response = Response::new(output).map_err(|_| Error::Application)?;
    core::pin::pin!(options.transfer(memory, environment, &mut requests, &mut response)).await
}

pub async fn server<const S: usize, const B: usize, Store: RandomAccess>(
    memory: &mut ConnectionMemory<S, B>,
    environment: Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
    mut options: session::Server<'_>,
    open: impl FnMut(&str) -> Result<Store, ()>,
) -> Result<Report, Error> {
    options.protocol = session::Protocol::Hq;
    let mut service = Service::new(open);
    core::pin::pin!(options.serve(memory, environment, &mut service)).await
}
