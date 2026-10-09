//! Stream resources and their byte/numerical operations.
//! The existing communication order is composed in application::global and
//! application::local; parts never advance that order independently.
pub mod imp;
