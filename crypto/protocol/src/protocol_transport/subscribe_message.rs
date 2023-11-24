use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
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
    // TODO i think we can use Public directly here
    pub public_key: [u8; 32],
    /// Signature to authenticate connecting party
    // TODO i think we can now use Signature directly as it implements serialize
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl SubscribeMessage {
    pub fn new(session_id: &str, pair: &sr25519::Pair) -> Self {
        let signature = pair.sign(session_id.as_bytes());
        Self {
            session_id: session_id.to_owned(),
            public_key: pair.public().0,
            signature: signature.0,
        }
    }

    pub fn account_id(&self) -> AccountId32 {
        self.public_key.into()
    }

    pub fn verify(&self) -> bool {
        sr25519::Pair::verify(
            &sr25519::Signature(self.signature),
            self.session_id.as_bytes(),
            &sr25519::Public(self.public_key),
        )
    }
}
