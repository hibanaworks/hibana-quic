//! Compatibility import path for the production phase-local TLS choreography.
//!
//! There is no separate flat Provider-RPC graph. Every caller of this module
//! projects the same staged Initial → Handshake → Unconfirmed → Confirmed →
//! Application flow used by `tls_owner::run_borrowed`.
pub use super::protocol_tls_phases::*;
