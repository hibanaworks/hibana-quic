//! ecn choreography, direct role locals and numerical implementation.
pub mod global;
pub(crate) mod imp;
pub use imp::{
    Error, Failure, FeedbackDelta, MarkedPackets, Metadata, PathIdentity, RxCounts,
    validate_feedback,
};
pub mod localside;
#[cfg(test)]
mod protocol_tests;
