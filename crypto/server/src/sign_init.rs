//! Message sent to Signing Client on protocol initiation.
use entropy_protocol::{SigningSessionInfo, ValidatorInfo};
use serde::{Deserialize, Serialize};

use crate::user::api::UserSignatureRequest;

/// Information passed to the Signing Client, to initiate the signing process.
/// Most of this information comes from a `Message` struct which gets propagated when a user's
/// signature request transaction is included in a finalized block.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignInit {
    /// Unique id of this signature (may be repeated if this party fails)
    pub signing_session_info: SigningSessionInfo,
    /// Participating nodes' info.
    pub validators_info: Vec<ValidatorInfo>,
}

impl SignInit {
    /// Creates new signing object based on passed in data
    #[allow(dead_code)]
    pub fn new(message: UserSignatureRequest, signing_session_info: SigningSessionInfo) -> Self {
        Self { signing_session_info, validators_info: message.validators_info }
    }
}
