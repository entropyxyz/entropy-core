use entropy_protocol::KeyParams;
use synedrion::{sessions::PrehashedMessage, KeyShare};

use crate::sign_init::SignInit;

/// Context for Signing Protocol execution.
#[derive(Debug, Clone)]
pub struct SignContext {
    /// Party context from block proposer
    pub sign_init: SignInit,
    /// Signing key share
    pub key_share: KeyShare<KeyParams>,
}

impl SignContext {
    pub fn new(sign_init: SignInit, key_share: KeyShare<KeyParams>) -> Self {
        Self { sign_init, key_share }
    }

    pub fn msg_to_sign(&self) -> &PrehashedMessage {
        &self.sign_init.signing_session_info.message_hash
    }
}
