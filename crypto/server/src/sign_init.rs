//! Message sent to Signing Client on protocol initiation.
use cggmp21::sessions::PrehashedMessage;
use entropy_shared::Message;
use serde::{Deserialize, Serialize};

/// Information passed to the Signing Client, to initiate the signing process.
/// Most of this information comes from a `Message` struct which gets propagated when a user's
/// signature request transaction is included in a finalized block.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignInit {
    /// Unique id of this signature (may be repeated if this party fails)
    pub sig_uid: String,
    /// Identifiers of the participating parties
    // TK: @JA: What to use for this? IP addresses? Substrate addresses? Substrate keys?
    // may overlap with ip_addresses below.
    pub signer_uids: Vec<String>,
    /// Hash of the message to sign
    pub msg: PrehashedMessage,
    /// Unique id of this signing party.
    /// If a prior party failed, repeat with a new `party_id`, but the same `sig_uid`
    pub party_uid: String,
    /// User's substrate key. The `key` in the kv-store.
    pub substrate_key: String,
    /// Participating nodes' IP addresses.
    pub ip_addresses: Vec<String>,
}

impl SignInit {
    // TODO(TK): option to make msg Bytes, and have `new` do input validation
    // todo: placeholder for actual logic
    #[allow(dead_code)]
    pub fn new(
        sig_uid: String,
        signer_uids: Vec<String>,
        msg: PrehashedMessage,
        party_uid: String,
        substrate_key: String,
        ip_addresses: Vec<String>,
    ) -> Self {
        Self { sig_uid, signer_uids, msg, party_uid, substrate_key, ip_addresses }
    }

    // TODO: remove when we have a real implementation
    // Generate temporary data for API testing.
    pub(crate) fn temporary_data(message: Message, key: String) -> Self {
        let digest: PrehashedMessage = message.sig_request.sig_hash.as_slice().try_into().unwrap();
        let raw_address = &message.account;
        let address_slice: &[u8; 32] =
            &raw_address.clone().try_into().expect("slice with incorrect length");
        let user = sp_core::crypto::AccountId32::new(*address_slice);
        let ip_addresses = message
            .validators_info
            .into_iter()
            .map(|validator_info| String::from_utf8(validator_info.ip_address).unwrap())
            .collect::<Vec<_>>();
        SignInit::new(
            key,
            vec!["test".to_string(), "test1".to_string()],
            digest,
            "test".to_string(),
            user.to_string(),
            ip_addresses,
        )
    }
}
