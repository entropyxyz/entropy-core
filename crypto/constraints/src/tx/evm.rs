//! This includes all EVM-architecture related types and functions.

use crate::tx::Architecture;
use serde_derive::{Deserialize, Serialize};
use web3::types::Address;
pub use web3::types::TransactionRequest as EvmTransactionRequest;

use super::{HasReceiver, HasSender};

/// EVM architecture
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EVM;

impl Architecture for EVM {
    type Address = Address;
    type TransactionRequest = EvmTransactionRequest;
}

impl HasSender<EVM> for EvmTransactionRequest {
    fn sender(&self) -> <EVM as Architecture>::Address {
        self.from
    }
}

impl HasReceiver<EVM> for EvmTransactionRequest {
    fn receiver(&self) -> Option<<EVM as Architecture>::Address> {
        self.to
    }
}
