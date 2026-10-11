//! File access and frame computations used by the HTTP/3 locals.
pub(super) mod wire;

pub(super) mod buffer;
pub(super) mod request;

pub(crate) mod input;

pub(crate) mod download;

pub(super) mod uri;
