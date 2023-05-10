use cggmp21::{sessions::PrehashedMessage, KeyShare, TestSchemeParams};
use kvdb::kv_manager::value::PartyId;

use crate::sign_init::SignInit;

/// Context for Signing Protocol execution.
#[derive(Debug, Clone)]
pub struct SignContext {
    /// Party context from block proposer
    pub sign_init: SignInit,
    /// Signing key share
    pub key_share: KeyShare<PartyId, TestSchemeParams>,
}

impl SignContext {
    #[allow(dead_code)]
    pub fn new(sign_init: SignInit, key_share: KeyShare<PartyId, TestSchemeParams>) -> Self {
        // TODO: the list of parties in `sign_init` should correspond to the one in `key_share`.
        // Need to either check or enforce it.
        Self { sign_init, key_share }
    }

    pub fn msg_to_sign(&self) -> &PrehashedMessage { &self.sign_init.msg }
}
