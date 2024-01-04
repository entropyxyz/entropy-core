// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
