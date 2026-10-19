//! Error type: every verifier rejection is an `Error::Reject` with a reason.
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Malformed or non-canonical input (verifier: reject).
    Decode(String),
    /// Well-formed input that fails a check (verifier: reject).
    Reject(String),
    /// Prover/issuer-side failure (exceptional value, exhausted spares, policy).
    Prover(String),
    /// The signing device is not available.
    DeviceUnavailable,
    /// Error from the ETSI BBS crate.
    Bbs(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(s) => write!(f, "decode: {s}"),
            Error::Reject(s) => write!(f, "{s}"),
            Error::Prover(s) => write!(f, "prover: {s}"),
            Error::DeviceUnavailable => write!(f, "device unavailable"),
            Error::Bbs(s) => write!(f, "bbs: {s}"),
        }
    }
}
impl std::error::Error for Error {}

impl From<bbs_cd::BbsError> for Error {
    fn from(e: bbs_cd::BbsError) -> Self {
        Error::Bbs(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn decode<T>(s: &str) -> Result<T> {
    Err(Error::Decode(s.to_string()))
}
