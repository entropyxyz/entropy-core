use synedrion::{sessions::PrehashedMessage, KeyShare, TestSchemeParams};

use crate::sign_init::SignInit;

/// Context for Signing Protocol execution.
#[derive(Debug, Clone)]
pub struct SignContext {
    /// Party context from block proposer
    pub sign_init: SignInit,
    /// Signing key share
    pub key_share: KeyShare<TestSchemeParams>,
}

impl SignContext {
    pub fn new(sign_init: SignInit, key_share: KeyShare<TestSchemeParams>) -> Self {
        Self { sign_init, key_share }
    }

    pub fn msg_to_sign(&self) -> &PrehashedMessage { &self.sign_init.msg }
}
