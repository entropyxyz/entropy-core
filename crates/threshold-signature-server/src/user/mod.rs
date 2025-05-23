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

//! Functionality and HTTP endpoints relating to user interaction
pub mod api;
pub mod errors;

use entropy_kvdb::kv_manager::value::{KvValue, PartyInfo};
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;

pub use self::errors::*;

#[cfg(test)]
pub(crate) mod tests;

/// User input, contains key (substrate key) and value (entropy shard)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserInputPartyInfo {
    /// User's substrate key
    pub key: AccountId32,
    // An encoded SecretKeyShare for this node
    pub value: KvValue,
}

impl TryInto<ParsedUserInputPartyInfo> for UserInputPartyInfo {
    type Error = UserErr;

    fn try_into(self) -> Result<ParsedUserInputPartyInfo, Self::Error> {
        let parsed_input = ParsedUserInputPartyInfo { key: self.key, value: self.value };
        Ok(parsed_input)
    }
}

/// Parsed user input
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ParsedUserInputPartyInfo {
    /// User's substrate key
    pub key: AccountId32,
    // An encoded SecretKeyShare for this node
    pub value: KvValue, // TODO(TK): write this type
}

// TODO(TK)
impl TryInto<PartyInfo> for ParsedUserInputPartyInfo {
    type Error = UserErr;

    fn try_into(self) -> Result<PartyInfo, Self::Error> {
        // todo!()
        Err(UserErr::InputValidation("error"))
    }
}
