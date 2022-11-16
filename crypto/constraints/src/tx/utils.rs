//! This module parses raw transactions (EVM, BTC, Substate) into a variety of components to allow constraints to be as generic as possible.

use crate::tx::{Architecture, BasicTransaction, FromAddress, ToAddress};
use serde_json::from_value;

/// Errors related to parsing raw transactions
#[derive(Debug, PartialEq)]
pub enum ParsingError {
    UnintelligableTransactionRequest,
    UndetectableArchitecture,
}

/// Takes raw transaction data and parses it into a basic transaction
pub fn parse_raw_tx_json<A: Architecture>(
    raw_tx: String,
) -> Result<BasicTransaction<A>, ParsingError> {
    let untyped_json_tx = serde_json::from_str(&raw_tx)
        .map_err(|e| ParsingError::UnintelligableTransactionRequest)?;

    // TODO JH : Insert more architectures here via else if let
    if let Ok(tx) = from_value::<A::TransactionRequest>(untyped_json_tx) {
        Ok(BasicTransaction { from: tx.sender(), to: tx.receiver() })
    } else {
        Err(ParsingError::UndetectableArchitecture)
    }
}
