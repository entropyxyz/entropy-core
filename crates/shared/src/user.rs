use crate::X25519PublicKey;
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;

/// Details of a TSS server
/// This is different from `entropy_shared::ValidatorInfo` in that it is used for interacting
/// with the client rather than with the chain - since it uses types which we cannot use in the
/// chain runtime
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: String,
    pub tss_account: AccountId32,
}
