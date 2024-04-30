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

use axum::{extract::State, Json};
use entropy_kvdb::kv_manager::KvManager;
use entropy_shared::{MIN_BALANCE, VERIFICATION_KEY_LENGTH};
use reqwest;
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::{str::FromStr, thread, time::Duration, time::SystemTime};
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32, OnlineClient,
};
use x25519_dalek::StaticSecret;

use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_staking_extension::pallet::ServerInfo},
        get_api, get_rpc, EntropyConfig,
    },
    get_signer_and_x25519_secret,
    helpers::{
        launch::FORBIDDEN_KEYS,
        substrate::{get_stash_address, query_chain, submit_transaction},
    },
    validation::{check_stale, EncryptedSignedMessage},
    validator::errors::ValidatorErr,
    AppState,
};

// TODO: find a proper batch size
pub const BATHC_SIZE_FOR_KEY_VALUE_GET: usize = 10;

/// Validation for if an account can cover tx fees for a tx
pub async fn check_balance_for_fees(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    address: &subxt::utils::AccountId32,
    min_balance: u128,
) -> Result<bool, ValidatorErr> {
    let balance_query = entropy::storage().system().account(address);
    let account_info = query_chain(api, rpc, balance_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Account does not exist, add balance"))?;
    let balance = account_info.data.free;
    let mut is_min_balance = false;
    if balance >= min_balance {
        is_min_balance = true
    };
    Ok(is_min_balance)
}

pub fn check_forbidden_key(key: &str) -> Result<(), ValidatorErr> {
    let forbidden = FORBIDDEN_KEYS.contains(&key);
    if forbidden {
        return Err(ValidatorErr::ForbiddenKey);
    }
    Ok(())
}
