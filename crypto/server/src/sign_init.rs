//! Message sent to Signing Client on protocol initiation.
use entropy_shared::{Message, X25519PublicKey};
use serde::{Deserialize, Serialize};
use synedrion::sessions::PrehashedMessage;

use crate::signing_client::SigningErr;

/// Information that is needed for talking to a validator
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ValidatorSendInfo {
    /// Participating nodes' IP addresses.
    pub ip_address: String,
    /// Participating nodes' x25519_public_key.
    pub x25519_public_key: X25519PublicKey,
}
/// Information passed to the Signing Client, to initiate the signing process.
/// Most of this information comes from a `Message` struct which gets propagated when a user's
/// signature request transaction is included in a finalized block.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignInit {
    /// Unique id of this signature (may be repeated if this party fails)
    pub sig_uid: String,
    /// Hash of the message to sign
    pub msg: PrehashedMessage,
    /// User's substrate key. The `key` in the kv-store.
    pub substrate_key: String,
    /// Participating nodes' info.
    pub validator_send_info: Vec<ValidatorSendInfo>,
}

impl SignInit {
    /// Creates new signing object based on passed in data
    #[allow(dead_code)]
    pub fn new(message: Message, tx_id: String) -> Result<Self, SigningErr> {
        let digest: PrehashedMessage = message.sig_request.sig_hash.as_slice().try_into()?;
        let raw_address = &message.account;
        let address_slice: &[u8; 32] = &raw_address
            .clone()
            .try_into()
            .map_err(|_| SigningErr::AddressConversionError("Invalid Length".to_string()))?;
        let user = sp_core::crypto::AccountId32::new(*address_slice);
        let validator_send_info_results: Result<Vec<ValidatorSendInfo>, _> = message
            .validators_info
            .into_iter()
            .map(|validator_info| {
                let ip_address = String::from_utf8(validator_info.ip_address)?;
                Ok::<ValidatorSendInfo, SigningErr>(ValidatorSendInfo {
                    ip_address,
                    x25519_public_key: validator_info.x25519_public_key,
                })
            })
            .collect();
        let validator_send_info = validator_send_info_results.map_err(SigningErr::from)?;

        Ok(Self {
            sig_uid: tx_id,
            msg: digest,
            substrate_key: user.to_string(),
            validator_send_info,
        })
    }
}
