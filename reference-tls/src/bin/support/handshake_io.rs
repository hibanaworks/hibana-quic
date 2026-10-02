//! Linux readiness/deadline helpers shared by the handshake-only adapters.
use hibana_quic_host::{
    async_io::{AsyncUdp, Reactor},
    udp::Received,
};
use std::{
    future::{Future, poll_fn},
    io,
    pin::pin,
    task::Poll,
    time::{Duration, Instant},
};
pub type HostReactor = Reactor<1, 4>;
pub type HostSocket<'a> = AsyncUdp<'a, 1, 4>;
pub const EXPIRED: &str = "handshake deadline expired; no success reported";

pub fn deadline(start: Instant, budget: Duration) -> Result<Instant, String> {
    start
        .checked_add(budget)
        .ok_or_else(|| "handshake deadline overflow".into())
}

/// Race the real readiness operation against its absolute deadline. The losing
/// future is dropped and unregisters its interest before another is created.
pub async fn before_deadline<T>(
    reactor: &HostReactor,
    deadline: Instant,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let mut operation = pin!(operation);
    let mut timer = pin!(reactor.sleep_until(deadline));
    poll_fn(|cx| {
        if let Poll::Ready(result) = timer.as_mut().poll(cx) {
            return Poll::Ready(result.and(Err(io::ErrorKind::TimedOut.into())));
        }
        operation.as_mut().poll(cx)
    })
    .await
}

pub async fn receive_until(
    reactor: &HostReactor,
    socket: &HostSocket<'_>,
    input: &mut [u8],
    deadline: Instant,
) -> io::Result<Option<Received>> {
    match before_deadline(reactor, deadline, socket.recv_from(input)).await {
        Ok(received) => Ok(Some(received)),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Ok(None),
        Err(error) => Err(error),
    }
}
