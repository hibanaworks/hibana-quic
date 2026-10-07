#![no_std]
#![allow(long_running_const_eval)]
#![forbid(unsafe_code)]
//! Experimental bounded QUIC v1 with direct Hibana choreography and async locals.
//! Core storage is caller-owned. See the qualification inventory for tested
//! revisions and the architecture ledger for incomplete lifecycle migration.

#[cfg(test)]
extern crate self as hibana_quic;

pub mod accounting;
pub mod bounded_tls;
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
pub mod tls_certificate;
pub mod tls_schedule;
pub mod tls_ticket;
pub mod tls_wire;

#[cfg(test)]
extern crate std;

pub mod tls_rsa;

pub mod connection_id;
pub mod early_data;
pub mod path;

pub mod trace;

pub mod runtime;

pub mod mailbox;

pub mod connection;

pub mod new_token;
