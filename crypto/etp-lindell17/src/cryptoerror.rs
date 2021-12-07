use core::fmt::{self, Display};

/// Result type with the `elliptic-curve` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Elliptic curve errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
//pub struct CryptoError;
pub enum CryptoError{
    K256EllipticCurveError(k256::elliptic_curve::Error),
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("etp crypto error")
    }
}

impl From<k256::elliptic_curve::Error> for CryptoError {
    fn from(err: k256::elliptic_curve::Error) -> Self {
        CryptoError::K256EllipticCurveError(err)
    }
}
