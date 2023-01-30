//! This includes all EVM-architecture related types and functions.
use entropy_shared::{Arch, Architecture, HasArch, HasReceiver, HasSender};
use serde_derive::{Deserialize, Serialize};
use web3::types::Address;
pub use web3::types::TransactionRequest as EvmTransactionRequest;

/// EVM architecture
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evm;

impl Architecture for Evm {
    type Address = Address;
    type TransactionRequest = EvmTransactionRequest;
}

impl HasSender<Evm> for EvmTransactionRequest {
    fn sender(&self) -> Option<<Evm as Architecture>::Address> { Some(self.from) }
}

impl HasReceiver<Evm> for EvmTransactionRequest {
    fn receiver(&self) -> Option<<Evm as Architecture>::Address> { self.to }
}

impl HasArch for Evm {
    fn arch() -> Arch { Arch::Evm }
}
