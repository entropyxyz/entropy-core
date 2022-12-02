// use crate::tx::{evm::EVM, Architecture, BasicTransaction};
use substrate_common::types::{ACLConstraint, Architecture, BasicTransaction, ACL};
use thiserror::Error;
/// Constraint errors.
#[derive(Error, Debug)]
pub enum ConstraintError {
    #[error("Constraint Evaluation error: {0}")]
    EvaluationError(String),
}

/// Interface for evaluating a constraint.
pub trait Constraint<A: Architecture> {
    fn eval(&self, tx: BasicTransaction<A>) -> Result<bool, ConstraintError>;
}

/// Generic implementation of Access Control Lists (Allow/Deny lists).
impl<A: Architecture> Constraint<A> for ACLConstraint<A> {
    fn eval(&self, tx: BasicTransaction<A>) -> Result<bool, ConstraintError> {
        if tx.to.is_none() {
            return Err(ConstraintError::EvaluationError(
                "Unspecified recipient in transaction".to_string(),
            ));
        }
        match self.acl_type {
            ACL::Allow => {
                return Ok(self.acl.contains(&tx.to.unwrap()));
            },
            ACL::Deny => {
                return Ok(!self.acl.contains(&tx.to.unwrap()));
            },
        }
    }
}
