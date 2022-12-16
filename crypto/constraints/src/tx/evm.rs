//! This includes all EVM-architecture related types and functions.
use serde_derive::{Deserialize, Serialize};
use substrate_common::{Arch, Architecture, HasArch, HasReceiver, HasSender};
use web3::types::Address;
pub use web3::types::TransactionRequest as EvmTransactionRequest;

/// EVM architecture
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EVM;

impl Architecture for EVM {
    type Address = Address;
    type TransactionRequest = EvmTransactionRequest;
}

impl HasSender<EVM> for EvmTransactionRequest {
    fn sender(&self) -> Option<<EVM as Architecture>::Address> {
        Some(self.from)
    }
}

impl HasReceiver<EVM> for EvmTransactionRequest {
    fn receiver(&self) -> Option<<EVM as Architecture>::Address> {
        self.to
    }
}

impl HasArch for EVM {
    fn arch() -> Arch {
        Arch::Evm
    }
}
