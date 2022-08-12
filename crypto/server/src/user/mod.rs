//! # User
//!
//! ## Overview
//!
//! Add a user to the network. Allows a user to send shards to nodes and have them store it.
//! User's substrate account acts as key value.
//!
//! ## Routes
//!
//! - /new_user/create - Post - Takes in a key and value for user
#![allow(dead_code)]
#![allow(unused_imports)]
pub mod api;
mod errors;

use std::{
  fs::File,
  io::{BufWriter, Write},
};

use kvdb::kv_manager::value::PartyInfo;
use rocket::{http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};

pub use self::errors::*;

#[cfg(test)]
mod tests;

/// User input, contains key (substrate key) and value (entropy shard)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserInputPartyInfo {
  /// User's substrate key
  pub key: String,
  // An encoded SecretKeyShare for this node
  pub value: Vec<u8>,
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
  pub key: String,
  // An encoded SecretKeyShare for this node
  pub value: Vec<u8>, // TODO(TK): write this type
}

// TODO(TK)
impl TryInto<PartyInfo> for ParsedUserInputPartyInfo {
  type Error = UserErr;

  fn try_into(self) -> Result<PartyInfo, Self::Error> {
    // todo!()
    Err(UserErr::InputValidation("error"))
  }
}
