use kvdb::kv_manager::PartyInfo;
use synedrion::sessions::PrehashedMessage;

use crate::sign_init::SignInit;

/// Context for Signing Protocol execution.
#[derive(Debug, Clone)]
pub struct SignContext {
    /// Party context from block proposer
    pub sign_init: SignInit,
    /// Signing key share  and party IDs
    pub party_info: PartyInfo,
}

impl SignContext {
    pub fn new(sign_init: SignInit, party_info: PartyInfo) -> Self {
        Self { sign_init, party_info }
    }

    pub fn msg_to_sign(&self) -> &PrehashedMessage { &self.sign_init.msg }
}
