//! Common authenticated connection startup with injected physical capabilities.
mod client;
mod server;
pub use client::connect;
pub use server::accept;
