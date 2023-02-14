use thiserror::Error;

#[cfg(test)]
mod tests;

pub mod constraints;
pub mod architectures;
pub mod tx;
pub mod utils;

pub use constraints::*;
pub use architectures::*;
pub use tx::*;
pub use utils::*;

/// Errors related to parsing and evaulating constraints.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Transaction request could not be parsed
    #[error("Invalid transaction request: {0}")]
    InvalidTransactionRequest(String),
    // /// Architecture associated with the transaction request could not be parsed
    // /// or is not supported
    // #[error("Invalid architecture: {0}")]
    // InvalidArchitecture(String),
    /// Transaction request did not meet constraint requirements.
    #[error("Constraint Evaluation error: {0}")]
    EvaluationError(String),
}
