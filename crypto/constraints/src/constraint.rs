use thiserror::Error;
use crate::tx::{evm::EVM, Architecture, BasicTransaction};
use alloc::{Vec};
/// Constraint errors.
#[derive(Error, Debug)]
pub enum ConstraintError {
    #[error("Constraint Evaluation error: {0}")]
    EvaluationError(&'a str),
}

/// Interface for evaluating a constraint.
pub trait Constraint<A: Architecture> {
    fn eval(&self, tx: BasicTransaction<A>) -> Result<bool, ConstraintError>;
}

pub enum ACL {
    Allow,
    Deny,
}

pub struct ACLConstraint<A: Architecture> {
    pub acl: Vec<A::Address>,
    pub acl_type: ACL,
} 

pub struct AccessControl<A: Architecture>{
    pub AllowedAddresses: Vec<A::Address>,
    pub DeniedAddresses: Vec<A::Address>,
}

impl <A: Architecture> Constraint<A> for ACLConstraint<A> {
    fn eval(&self, tx: BasicTransaction<A>) -> Result<bool, ConstraintError> {
        if tx.to.is_none() {
            return Err(ConstraintError::EvaluationError("Unspecified recipient in transaction".to_string()));
        }
        match self.acl_type {
            ACL::Allow => {
                if !self.acl.contains(&tx.to.unwrap()) {
                    return Ok(false);
                }
            },
            ACL::Deny => {
                if self.acl.contains(&tx.to.unwrap()) {
                    return Ok(false);
                }
            },
            _ => {
                return Err(ConstraintError::EvaluationError("Incorrect ACL type".to_string()));
            },
        }
        Ok(true)
    }
}
