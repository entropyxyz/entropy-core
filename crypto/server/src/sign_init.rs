//! Message sent to Signing Client on protocol initiation.
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use synedrion::sessions::PrehashedMessage;

use crate::{
    signing_client::ProtocolErr,
    user::api::{UserTransactionRequest, ValidatorInfo},
};

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
    pub validators_info: Vec<ValidatorInfo>,
}

impl SignInit {
    /// Creates new signing object based on passed in data
    #[allow(dead_code)]
    pub fn new(
        message: UserTransactionRequest,
        sig_hash: String,
        tx_id: String,
        user: AccountId32,
    ) -> Result<Self, ProtocolErr> {
        let digest: PrehashedMessage = hex::decode(sig_hash)?
            .try_into()
            .map_err(|_| ProtocolErr::Conversion("Digest Conversion"))?;

        Ok(Self {
            sig_uid: tx_id,
            msg: digest,
            substrate_key: user.to_string(),
            validators_info: message.validators_info,
        })
    }
}
