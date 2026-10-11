//! Allocation-free native errors. Protocol errors stay in hibana-quic.
use core::fmt;
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    WouldBlock,
    Interrupted,
    InvalidInput,
    InvalidData,
    NotConnected,
    AlreadyExists,
    BrokenPipe,
    NotFound,
    WriteZero,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    code: Option<i32>,
    message: &'static str,
}
impl Error {
    pub const fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            code: None,
            message,
        }
    }
    pub fn last_os_error() -> Self {
        Self::from_raw_os_error(crate::sys::os::errno())
    }
    pub fn from_raw_os_error(code: i32) -> Self {
        #[cfg(target_os = "linux")]
        const WOULD_BLOCK: i32 = 11;
        #[cfg(target_os = "macos")]
        const WOULD_BLOCK: i32 = 35;
        #[cfg(target_os = "linux")]
        const NOT_CONNECTED: i32 = 107;
        #[cfg(target_os = "macos")]
        const NOT_CONNECTED: i32 = 57;
        let kind = match code {
            WOULD_BLOCK => ErrorKind::WouldBlock,
            4 => ErrorKind::Interrupted,
            22 => ErrorKind::InvalidInput,
            NOT_CONNECTED => ErrorKind::NotConnected,
            17 => ErrorKind::AlreadyExists,
            32 => ErrorKind::BrokenPipe,
            2 => ErrorKind::NotFound,
            _ => ErrorKind::Other,
        };
        Self {
            kind,
            code: Some(code),
            message: "native operation failed",
        }
    }
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
    pub const fn raw_os_error(&self) -> Option<i32> {
        self.code
    }
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind, "native operation failed")
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(f, "{} ({:?}, errno {code})", self.message, self.kind),
            None => write!(f, "{} ({:?})", self.message, self.kind),
        }
    }
}
impl core::error::Error for Error {}
