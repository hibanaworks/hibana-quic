#![no_std]
#![allow(long_running_const_eval)]
#![forbid(unsafe_code)]
//! Experimental bounded QUIC v1 with direct Hibana choreography and async locals.
//! Core storage is caller-owned. See the qualification inventory for tested
//! revisions and the architecture ledger for incomplete lifecycle migration.

#[cfg(test)]
extern crate self as hibana_quic;

pub mod accounting;
pub mod carrier;
pub mod crypto;
pub mod version;

pub mod flights;
pub mod flow;
pub mod handshake;
pub mod key_exchange;

pub mod ecn;
pub mod packet;
pub mod parameters;

pub mod recovery;
pub mod retry;
pub mod storage;
pub mod streams;
pub mod tls;

#[cfg(test)]
extern crate std;

pub mod connection_id;
pub mod early_data;
pub mod path;

pub mod trace;

pub mod runtime;

pub mod mailbox;

pub mod quic;

pub mod new_token;

pub mod http3;

/// Physical UDP and monotonic-clock contracts for adapter implementers.
pub mod io;
