//! This module provides generic transaction types for constraints to use, unsigned transaction
//! parsing utilities, and architecture information about the differet ways transactions are handled
//! on each platform (EVM, BTC, Substrate, etc).
pub mod evm;
pub mod utils;

use serde::{Deserialize, Serialize};
use serde_derive::{Deserialize as DeserializeDerive, Serialize as SerializeDerive};
pub use utils::*;

/// Errors related to parsing raw transactions
pub enum Arch {
    EVM,
    BTC,
}

/// Basic transaction that has a sender and receiver with single accounts
#[derive(Default, Debug, Clone, PartialEq, SerializeDerive, DeserializeDerive)]
pub struct BasicTransaction<A: Architecture> {
    pub from: Option<A::Address>,
    pub to: Option<A::Address>,
}

/// Trait that defines types for the architecture the transaction is for
pub trait Architecture: Serialize + for<'de> Deserialize<'de> + HasArch {
    /// Account type for that chain(SS58, H160, etc)
    type Address: Eq + Serialize + for<'de> Deserialize<'de>;
    type TransactionRequest: HasSender<Self>
        + HasReceiver<Self>
        + Serialize
        + for<'de> Deserialize<'de>;
    type TransactionHash: Serialize + for<'de> Deserialize<'de>;
}

pub trait HasArch {
    fn arch() -> Arch;
}

/// Trait for getting the the sender of a transaction
pub trait HasSender<A: Architecture + ?Sized> {
    fn sender(&self) -> Option<A::Address>;
}

/// Trait for getting the the receiver of a transaction
pub trait HasReceiver<A: Architecture + ?Sized> {
    fn receiver(&self) -> Option<A::Address>;
}
