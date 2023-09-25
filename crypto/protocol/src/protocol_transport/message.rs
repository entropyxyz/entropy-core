use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use subxt::utils::AccountId32;
use subxt_signer::sr25519;

/// A message sent by a party when initiating a websocket connection to participate
/// in the signing or DKG protcol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SubscribeMessage {
    /// Protocol session identifier
    pub session_id: String,
    /// Public key of connecting party
    pub public_key: [u8; 32],
    /// Signature to authenticate connecting party
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl SubscribeMessage {
    pub fn new(session_id: &str, sk: &sr25519::Keypair) -> Self {
        let signature = sk.sign(session_id.as_bytes());
        Self {
            session_id: session_id.to_owned(),
            public_key: sk.public_key().0,
            signature: signature.0,
        }
    }

    pub fn account_id(&self) -> AccountId32 { self.public_key.into() }

    pub fn verify(&self) -> bool {
        sr25519::verify(
            &sr25519::Signature(self.signature),
            self.session_id.as_bytes(),
            &sr25519::PublicKey(self.public_key),
        )
    }
}
