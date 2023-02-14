//! This includes the supported architectures and traits for adding new ones.

use entropy_shared::Arch;
use crate::Error;

use serde::{Deserialize, Serialize};

pub use evm::*;

/// Trait for defining important types associated with an architecture.
pub trait Architecture: Serialize + for<'de> Deserialize<'de> {
    /// Account type for that chain(SS58, H160, etc)
    type Address: Eq + Serialize + for<'de> Deserialize<'de>;
    /// Transaction request type for unsigned transactions
    type TransactionRequest: GetSender<Self>
        + GetReceiver<Self>
        + Serialize
        + for<'de> Deserialize<'de>
        + Parse<Self>;
}

/// Trait for getting the the sender of a transaction.
pub trait GetSender<A: Architecture> {
    fn sender(&self) -> Option<A::Address>;
}

/// Trait for getting the the receiver of a transaction.
pub trait GetReceiver<A: Architecture> {
    fn receiver(&self) -> Option<A::Address>;
}

/// Trait for parsing a raw transaction request into its native transaction request struct.
pub trait Parse<A: Architecture> {
    fn parse(raw_tx: String) -> Result<A::TransactionRequest, Error>;
}

/// Trait for getting the Arch of a transaction request.
pub trait GetArch {
    fn arch() -> Arch;
}

/// EVM architecture
pub mod evm {
    use super::*;
    use ethers_core::types::NameOrAddress;
    pub use ethers_core::types::{Address as EvmAddress, transaction::request::TransactionRequest as EvmTransactionRequest};
    use rlp::Rlp;

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Evm;

    impl Architecture for Evm {
        type Address = EvmAddress;
        type TransactionRequest = EvmTransactionRequest;
    }

    impl GetSender<Evm> for <Evm as Architecture>::TransactionRequest {
        fn sender(&self) -> Option<<Evm as Architecture>::Address> {
            self.from
        }
    }

    impl GetReceiver<Evm> for <Evm as Architecture>::TransactionRequest {
        fn receiver(&self) -> Option<<Evm as Architecture>::Address> {
            match &self.to {
                Some(to) => match to {
                    NameOrAddress::Address(addr) => Some(addr.to_owned()),
                    // This should never get returned because we Error on ENS names in the `parse` function
                    NameOrAddress::Name(_) => None,
                },
                None => None,
            }
        }
    }

    impl GetArch for <Evm as Architecture>::TransactionRequest {
        fn arch() -> Arch {
            Arch::Evm
        }
    }

    impl Parse<Evm> for <Evm as Architecture>::TransactionRequest {
        fn parse(hex_rlp_raw_tx: String) -> Result<<Evm as Architecture>::TransactionRequest, Error> {
            let bytes = hex::decode(hex_rlp_raw_tx.replace("0x", "").clone()).map_err(|e| Error::InvalidTransactionRequest(format!("Unable to parse to RLP: {}", e)))?;
            let rlp = Rlp::new(&bytes);
            match Self::decode_unsigned_rlp(&rlp) {
                Ok(tx) => match tx.to {
                    // Clients shouldn't even be able to serialize tx reqs with ENS names, but it it does somehow, err
                    Some(NameOrAddress::Name(_)) => Err(Error::InvalidTransactionRequest("ENS recipients not supported. Resolve to an address first.".to_string())),
                    _ => Ok(tx),
                },
                Err(e) => Err(Error::InvalidTransactionRequest(format!("Unable to decode string: {}", e))),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::str::FromStr;

        use super::*;

        #[test]
        fn test_evm_parse() {
            // This is `serializedUnsignedTx` from entropy-js threshold-server tests
            let raw_tx = "0xef01808094772b9a9e8aa1c9db861c6611a82d251db4fac990019243726561746564204f6e20456e74726f7079018080".to_string();
            let tx = EvmTransactionRequest::parse(raw_tx).unwrap();
            assert_eq!(tx.sender(), None);
            assert_eq!(tx.receiver(), Some(EvmAddress::from_str("772b9a9e8aa1c9db861c6611a82d251db4fac990").unwrap())); // manually removed the 0x
        }
}

}
