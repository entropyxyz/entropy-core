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
mod errors;

use std::{
    fs::File,
    io::{BufWriter, Write},
};

use kvdb::kv_manager::{
    helpers::deserialize,
    value::{KvValue, PartyInfo},
    PartyId,
};
use rocket::{http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use subxt::ext::sp_runtime::AccountId32;
use synedrion::{KeyShare, TestSchemeParams};

pub use self::errors::*;

#[cfg(test)]
mod tests;

/// A key-share submitted by the user when registering
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserInputPartyInfo {
    /// Bincode encoded Synedrion KeyShare
    pub key_share: Vec<u8>,
    /// Party IDs
    pub party_ids: Vec<AccountId32>,
}

impl TryInto<PartyInfo> for UserInputPartyInfo {
    type Error = UserErr;

    fn try_into(self) -> Result<PartyInfo, Self::Error> {
        let share: KeyShare<TestSchemeParams> = deserialize(&self.key_share)
            .ok_or(UserErr::InputValidation("Cannot deserialize key-share"))?;
        let party_ids: Vec<PartyId> = self.party_ids.into_iter().map(PartyId::new).collect();
        Ok(PartyInfo { share, party_ids })
    }
}
