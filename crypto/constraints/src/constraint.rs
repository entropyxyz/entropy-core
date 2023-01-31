use entropy_shared::{Acl, AclKind, Architecture, BasicTransaction};
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
impl<A: Architecture> Constraint<A> for Acl<A::Address> {
    fn eval(&self, tx: BasicTransaction<A>) -> Result<bool, ConstraintError> {
        if !self.allow_null_recipient && tx.to.is_none() {
            return Err(ConstraintError::EvaluationError(
                "Unspecified recipient in transaction".to_string(),
            ));
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
