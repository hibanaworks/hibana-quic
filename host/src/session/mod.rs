//! Run projected application roles over authenticated bidirectional QUIC streams.
//! The network carrier, frame ownership and native executor are owned here.
use crate::io::{HostClock, HostReactor, before_deadline};
use hibana::{Endpoint, runtime::program::RoleProgram};
use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};
pub mod local;
pub use hibana_quic::session::Protocol;
pub struct Client {
    pub remote: SocketAddr,
    pub server_name: String,
    pub ca: PathBuf,
    pub protocol: Protocol,
    pub timeout: Duration,
}
pub struct Server {
    pub listen: SocketAddr,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub protocol: Protocol,
    pub timeout: Duration,
}
pub type Result<T> = std::result::Result<T, String>;
/// Drive a caller's projected client localside and its network transport together.
pub fn client<const ROLE: u8, E: core::fmt::Debug>(
    options: Client,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<()> {
    let reactor = HostReactor::<4, 8>::new().map_err(|e| e.to_string())?;
    let clock = HostClock::new(&reactor, Instant::now());
    let deadline = clock
        .start
        .checked_add(options.timeout)
        .ok_or("deadline overflow")?;
    let result = reactor
        .block_on(Box::pin(before_deadline(
            &clock,
            deadline,
            local::client(&reactor, &clock, options, peer, program, application),
        )))
        .map_err(|e| e.to_string())?;
    if reactor.active_resources() != (0, 0) {
        return Err("unretired native resources".into());
    }
    result
}
/// Drive a caller's projected server localside on one accepted connection.
pub fn server<const ROLE: u8, E: core::fmt::Debug>(
    options: Server,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<()> {
    let reactor = HostReactor::<4, 8>::new().map_err(|e| e.to_string())?;
    let clock = HostClock::new(&reactor, Instant::now());
    let deadline = clock
        .start
        .checked_add(options.timeout)
        .ok_or("deadline overflow")?;
    let result = reactor
        .block_on(Box::pin(before_deadline(
            &clock,
            deadline,
            local::server(&reactor, &clock, options, peer, program, application),
        )))
        .map_err(|e| e.to_string())?;
    if reactor.active_resources() != (0, 0) {
        return Err("unretired native resources".into());
    }
    result
}
