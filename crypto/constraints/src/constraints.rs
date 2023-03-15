//! Contains the traits and implementations of each supported constraint.

use entropy_shared::{Acl, AclKind};
use ethers_core::types::{NameOrAddress, Address, H160};

use crate::{Architecture, BasicTransaction, Error, Evm};

/// Constraints must implement an evaluation trait that parses.
pub trait Evaluate<A: Architecture> {
    fn eval(&self, tx: A::TransactionRequest) -> Result<bool, Error>;
}

/// Generic implementation of Access Control Lists (Allow/Deny lists).
// impl<A: Architecture> Evaluate<A> for Acl<A::Address> {
//     fn eval(&self, tx: BasicTransaction<A>) -> Result<bool, Error> {
//         if !self.allow_null_recipient && tx.to.is_none() {
//             return Err(Error::EvaluationError("Unspecified recipient in transaction".to_string()));
//         }
//         if self.allow_null_recipient && tx.to.is_none() {
//             return Ok(true);
//         }
//         match self.kind {
//             AclKind::Allow => Ok(self.addresses.contains(&tx.to.unwrap())),
//             AclKind::Deny => Ok(!self.addresses.contains(&tx.to.unwrap())),
//         }
//     }
// }

impl Evaluate<Evm> for Acl<[u8; 20]> {
    fn eval(&self, tx: <Evm as Architecture>::TransactionRequest) -> Result<bool, Error> {
        if tx.to.is_none() {
            return match self.allow_null_recipient {
                true => Ok(true),
                false => Err(Error::EvaluationError("Unspecified recipient in transaction".to_string()))
            }
        }

        let converted_addresses: Vec<NameOrAddress> = self.addresses.iter().map(|a| NameOrAddress::Address(Address::from(H160::from(*a)))).collect();

        match self.kind {
            AclKind::Allow => Ok(converted_addresses.contains(&tx.to.unwrap())),
            AclKind::Deny => Ok(!converted_addresses.contains(&tx.to.unwrap())),
        }
    }
}
