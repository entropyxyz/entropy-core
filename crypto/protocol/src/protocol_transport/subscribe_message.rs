use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use subxt::utils::AccountId32;

/// A message sent by a party when initiating a websocket connection to participate
/// in the signing or DKG protcol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SubscribeMessage {
    /// Protocol session identifier
    pub session_id: String,
    /// Public key of connecting party
    pub public_key: sr25519::Public,
    /// Signature to authenticate connecting party
    pub signature: sr25519::Signature,
}

impl SubscribeMessage {
    pub fn new(session_id: &str, pair: &sr25519::Pair) -> Self {
        let signature = pair.sign(session_id.as_bytes());
        Self { session_id: session_id.to_owned(), public_key: pair.public(), signature }
    }

    pub fn account_id(&self) -> AccountId32 {
        self.public_key.0.into()
    }

    pub fn verify(&self) -> bool {
        sr25519::Pair::verify(&self.signature, self.session_id.as_bytes(), &self.public_key)
    }
}
