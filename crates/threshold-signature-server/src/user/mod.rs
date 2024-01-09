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

//! # User
//!
//! ## Overview
//!
//! Add a user to the network. Allows a user to send shards to nodes and have them store it.
//! User's substrate account acts as key value.
//!
//! ## Routes
//!
//! - `/user/new` - POST - Takes in a key and value for user
//! - `/user/tx` - POST - Submit a transaction to be signed
#![allow(dead_code)]
#![allow(unused_imports)]
pub mod api;
pub mod errors;

use std::{
    fs::File,
    io::{BufWriter, Write},
};

use entropy_kvdb::kv_manager::value::{KvValue, PartyInfo};
use serde::{Deserialize, Serialize};
use subxt::ext::sp_runtime::AccountId32;

pub use self::errors::*;

#[cfg(test)]
mod tests;

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
