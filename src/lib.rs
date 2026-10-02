#![no_std]
#![forbid(unsafe_code)]
//! Bounded QUIC v1 building blocks. This crate is not yet a QUIC endpoint.
//! No interop, full TLS, Pico HIL, or source-level verification claim is made.

pub mod accounting;
pub mod bounded_tls;
pub mod carrier;
pub mod crypto;
pub mod driver;
pub mod flights;
pub mod flow;
pub mod handshake;
pub mod key_exchange;
pub mod lifecycle;
pub mod handshake_endpoint;
pub mod ecn;
pub mod packet;
pub mod parameters;
pub mod protocol;
pub mod recovery;
pub mod retry;
pub mod storage;
pub mod streams;
pub mod tls;
pub mod tls_certificate;
pub mod tls_schedule;
pub mod tls_ticket;
pub mod tls_wire;
pub mod transport_endpoint;

#[cfg(test)]
extern crate std;

pub mod tls_rsa;

pub mod early_data;
pub mod early_control;
pub mod connection_id;
pub mod path;
pub mod migration;

pub mod idle;

pub mod early_send;

pub mod version_negotiation;

pub mod trace;

pub mod runtime;

pub mod mailbox;

pub mod roles;
