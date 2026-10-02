//! Readable role-local implementations over one projected choreography.
//!
//! These roles own real resources. The enclosing session retains endpoint
//! values until every role finishes; no actor recreates or synchronously polls
//! another actor's endpoint. Numerical buffer/descriptor checks remain local.
pub mod packet_protection;
pub mod protocol;

pub mod client;
