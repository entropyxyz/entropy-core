use serde_json::from_value;

use crate::tx::{Architecture, BasicTransaction, HasReceiver, HasSender};

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
        .map_err(|_e| ParsingError::UnintelligableTransactionRequest)?;

    match from_value::<A::TransactionRequest>(untyped_json_tx) {
        Ok(tx) => Ok(BasicTransaction { from: tx.sender(), to: tx.receiver() }),
        Err(_e) => Err(ParsingError::UndetectableArchitecture),
    }
}
