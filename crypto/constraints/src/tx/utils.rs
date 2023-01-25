use serde_json::from_value;
use substrate_common::{Architecture, BasicTransaction, HasReceiver, HasSender};
use thiserror::Error;

/// Errors related to parsing raw transactions
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid transaction request: {0}")]
    InvalidTransactionRequest(#[from] serde_json::Error),
}

/// Takes raw transaction data and parses it into a basic transaction
/// TODO JH : 'from' field won't exist in raw_tx for EVM transactions, so we need to get it from
/// onchain somehow (during sig request)
pub fn parse_tx_request_json<A: Architecture>(
    raw_tx: String,
) -> Result<BasicTransaction<A>, Error> {
    let untyped_json_tx = serde_json::from_str(&raw_tx)?;
    match from_value::<A::TransactionRequest>(untyped_json_tx) {
        Ok(tx) => Ok(BasicTransaction { from: tx.sender(), to: tx.receiver() }),
        Err(e) => Err(e.into()),
    }
}
