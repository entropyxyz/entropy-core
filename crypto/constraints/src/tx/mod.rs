pub mod evm;
pub mod utils;

pub use tx::*;
pub use utils::*;

pub(crate) mod tx {
    use serde::{Deserialize, Serialize};
    use serde_derive::{Deserialize as DeserializeDerive, Serialize as SerializeDerive};
    /// Basic transaction that has a sender and receiver with single accounts
    #[derive(Default, Debug, Clone, PartialEq, SerializeDerive, DeserializeDerive)]
    pub struct BasicTransaction<A: Architecture> {
        pub from: Option<A::Address>,
        pub to: Option<A::Address>,
        // pub amount: A::Balance
    }

    /// Trait that defines types for the architecture the transaction is for
    pub trait Architecture: Serialize {
        /// Account type for that chain(SS58, H160, etc)
        type Address: Serialize + for<'de> Deserialize<'de>;
        type TransactionRequest: FromAddress<Self>
            + ToAddress<Self>
            + Serialize
            + for<'de> Deserialize<'de>;
        // Units for that chain or something
        // type Balance: PartialEq
    }

    /// Trait for getting the the sender of a transaction
    pub trait FromAddress<A: Architecture + ?Sized> {
        fn sender(&self) -> Option<A::Address>;
    }

    /// Trait for getting the the receiver of a transaction
    pub trait ToAddress<A: Architecture + ?Sized> {
        fn receiver(&self) -> Option<A::Address>;
    }
}
