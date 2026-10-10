//! retry choreography, direct role locals and numerical implementation.
pub mod global;
pub(crate) mod imp;
pub use imp::Error as TokenError;
pub use imp::admission;
pub use imp::{
    CheckedRetry, ClientAddress, DEFAULT_TOKEN_LIFETIME_US, MAX_TOKEN_LIFETIME_US, RetryTokens,
    TOKEN_LEN, TokenContext, ValidatedToken, encode_retry, validate_retry,
};
pub mod localside;

pub use imp::admission::AdmittedInitial;
/// Admission failure; a failed choreography must not be resumed.
#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Label(u8),
    Resolver(hibana::runtime::resolver::ResolverError),
    Io(crate::io::IoError),
    Entropy(crate::entropy::Unavailable),
    Token(imp::Error),
    Endpoint(hibana::EndpointError),
    Attach(hibana::runtime::AttachError),
    Transport(hibana::runtime::transport::TransportError),
}
impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
        Self::Invalid(value)
    }
}
impl From<crate::io::IoError> for Error {
    fn from(value: crate::io::IoError) -> Self {
        Self::Io(value)
    }
}
impl From<crate::entropy::Unavailable> for Error {
    fn from(value: crate::entropy::Unavailable) -> Self {
        Self::Entropy(value)
    }
}
impl From<imp::Error> for Error {
    fn from(value: imp::Error) -> Self {
        Self::Token(value)
    }
}
impl From<hibana::EndpointError> for Error {
    fn from(value: hibana::EndpointError) -> Self {
        Self::Endpoint(value)
    }
}
impl From<hibana::runtime::AttachError> for Error {
    fn from(value: hibana::runtime::AttachError) -> Self {
        Self::Attach(value)
    }
}
impl From<hibana::runtime::transport::TransportError> for Error {
    fn from(value: hibana::runtime::transport::TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<hibana::runtime::resolver::ResolverError> for Error {
    fn from(value: hibana::runtime::resolver::ResolverError) -> Self {
        Self::Resolver(value)
    }
}
