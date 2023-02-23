//! Contains the traits and implementations of each supported constraint.

use entropy_shared::{Acl, AclKind};

use crate::{Architecture, BasicTransaction, Error};

/// Constraints must implement an evaluation trait that parses.
pub trait Evaluate<A: Architecture> {
    fn eval(&self, tx: BasicTransaction<A>) -> Result<bool, Error>;
}

/// Generic implementation of Access Control Lists (Allow/Deny lists).
impl<A: Architecture> Evaluate<A> for Acl<A::Address> {
    fn eval(&self, tx: BasicTransaction<A>) -> Result<bool, Error> {
        if !self.allow_null_recipient && tx.to.is_none() {
            return Err(Error::EvaluationError("Unspecified recipient in transaction".to_string()));
        }
        if self.allow_null_recipient && tx.to.is_none() {
            return Ok(true);
        }
        match self.kind {
            AclKind::Allow => Ok(self.addresses.contains(&tx.to.unwrap())),
            AclKind::Deny => Ok(!self.addresses.contains(&tx.to.unwrap())),
        }
    }
}
