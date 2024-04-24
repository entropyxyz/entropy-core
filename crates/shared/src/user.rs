use crate::X25519PublicKey;
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;

/// Details of a TSS server
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: String,
    pub tss_account: AccountId32,
}
