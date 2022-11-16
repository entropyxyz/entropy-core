//! This includes all EVM-architecture related types and functions.

use crate::tx::Architecture;
pub use serde_derive::{Deserialize, Serialize};
pub use web3::types::Address;
pub use web3::types::TransactionRequest as EvmTransactionRequest;

use super::{FromAddress, ToAddress};

/// EVM architecture
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EVM;

impl Architecture for EVM {
    type Address = Address;
    type TransactionRequest = EvmTransactionRequest;
}

impl FromAddress<EVM> for EvmTransactionRequest {
    fn sender(&self) -> Option<<EVM as Architecture>::Address> {
        Some(self.from)
    }
}

impl ToAddress<EVM> for EvmTransactionRequest {
    fn receiver(&self) -> Option<<EVM as Architecture>::Address> {
        self.to
    }
}

// Parsed unsigned EVM transaction
// #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub struct UnsignedEvmTransaction {
//     pub from: String,
//     pub gas: String,
//     pub max_fee_per_gas: String,
//     pub max_priority_fee_per_gas: String,
//     pub input: String,
//     pub nonce: String,
//     pub to: String,
//     pub value: String,
// }

// Parsed signed EVM transaction
// #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub struct SignedEvmTransaction {
//     pub from: String,
//     pub gas: String,
//     pub max_fee_per_gas: String,
//     pub max_priority_fee_per_gas: String,
//     pub input: String,
//     pub nonce: String,
//     pub to: String,
//     pub value: String,
//     pub v: String,
//     pub r: String,
//     pub s: String,
//     pub hash: String,
// }
