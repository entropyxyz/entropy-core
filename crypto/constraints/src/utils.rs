use serde_json::from_value;

use crate::{Architecture, BasicTransaction, Error, GetReceiver, GetSender};

/// Takes a serialized transaction request from the client and parses it to the associated
/// Architecture
pub fn parse_tx_request_json<A: Architecture>(
    raw_tx: String,
) -> Result<BasicTransaction<A>, Error> {
    let untyped_json_tx = serde_json::from_str(&raw_tx)
        .map_err(|e| Error::InvalidTransactionRequest(e.to_string()))?;
    match from_value::<A::TransactionRequest>(untyped_json_tx) {
        Ok(tx) => Ok(BasicTransaction { from: tx.sender(), to: tx.receiver() }),
        Err(e) => Err(Error::InvalidTransactionRequest(e.to_string())),
    }
}
