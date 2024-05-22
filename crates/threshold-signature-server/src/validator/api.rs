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
        substrate::{get_stash_address, get_subgroup, query_chain, submit_transaction},
    },
    validation::{check_stale, EncryptedSignedMessage},
    validator::errors::ValidatorErr,
    AppState,
};

/// A set of signature request account IDs for which keyshares are requested, given as SS58 encoded
/// strings.
///
/// This is the HTTP request body to `/validator/sync_kvdb`.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Keys {
    pub keys: Vec<String>,
    pub timestamp: SystemTime,
}

/// A set of encrypted keyshares.
///
/// This is the HTTP response body to `/validator/sync_kvdb`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Values {
    pub values: Vec<EncryptedSignedMessage>,
}

// TODO: find a proper batch size
pub const BATHC_SIZE_FOR_KEY_VALUE_GET: usize = 10;

/// Syncs a validator by:
/// - getting all registered keys from chain
/// - finding a server in their subgroup that is synced
/// - getting all shards from said validator
#[tracing::instrument(skip(kv_store))]
pub async fn sync_validator(dev: bool, endpoint: &str, kv_store: &KvManager) {
    let api = get_api(endpoint).await.expect("Issue acquiring chain API");
    let rpc = get_rpc(endpoint).await.expect("Issue acquiring chain RPC");
    let mut is_syncing = true;
    let sleep_time = Duration::from_secs(20);
    // wait for chain to be fully synced before starting key swap
    while is_syncing {
        let health = rpc.system_health().await.expect("Issue checking chain health");
        is_syncing = health.is_syncing;
        if is_syncing {
            tracing::info!("Syncing chain");
            thread::sleep(sleep_time);
        }
    }
    let (signer, x25519_secret) =
        get_signer_and_x25519_secret(kv_store).await.expect("Issue acquiring threshold keypairs");
    let has_fee_balance = check_balance_for_fees(&api, &rpc, signer.account_id(), MIN_BALANCE)
        .await
        .expect("Issue checking chain for signer balance");
    if !has_fee_balance {
        panic!("threshold account needs balance: {:?}", signer.account_id());
    }
    // if not in subgroup retry until you are
    let mut my_subgroup = get_subgroup(&api, &rpc, signer.account_id()).await;
    while my_subgroup.is_err() {
        tracing::warn!("The signing account is not in the validator set, retrying sync");
        thread::sleep(sleep_time);
        my_subgroup = Ok(get_subgroup(&api, &rpc, signer.account_id())
            .await
            .expect("Failed to get subgroup."));
    }
    let subgroup = my_subgroup.expect("Failed to get subgroup.");
    let validator_stash = get_stash_address(&api, &rpc, signer.account_id())
        .await
        .expect("Failed to get threshold server's stash address.");
    let key_server_info = get_random_server_info(&api, &rpc, subgroup, validator_stash)
        .await
        .expect("Issue getting registered keys from chain.");
    let all_keys = get_all_keys(&api, &rpc).await.expect("failed to get all keys.");
    get_and_store_values(
        all_keys,
        kv_store,
        BATHC_SIZE_FOR_KEY_VALUE_GET,
        dev,
        key_server_info,
        &signer,
        &x25519_secret,
    )
    .await
    .expect("failed to get and store all values");
    tell_chain_syncing_is_done(&api, &rpc, &signer).await.expect("failed to finish chain sync.");
}

/// Endpoint to allow a new node to sync their kvdb with a member of their subgroup
#[tracing::instrument(skip_all, fields(signing_address))]
pub async fn sync_kvdb(
    State(app_state): State<AppState>,
    Json(encrypted_msg): Json<EncryptedSignedMessage>,
) -> Result<Json<Values>, ValidatorErr> {
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    let (signer, x25519_secret_key) = get_signer_and_x25519_secret(&app_state.kv_store).await?;
    let decrypted_message = encrypted_msg.decrypt(&x25519_secret_key, &[])?;

    tracing::Span::current().record("signing_address", decrypted_message.account_id().to_string());
    let sender_account_id = SubxtAccountId32(decrypted_message.sender.into());
    let keys: Keys = serde_json::from_slice(&decrypted_message.message)?;
    check_stale(keys.timestamp)?;

    let signing_address = decrypted_message.account_id();
    check_in_subgroup(&api, &rpc, &signer, &signing_address).await?;

    let sender_encryption_pk = {
        let sender_stash_address = get_stash_address(&api, &rpc, &sender_account_id).await?;
        let block_hash = rpc.chain_get_block_hash(None).await?;
        let threshold_address_query =
            entropy::storage().staking_extension().threshold_servers(sender_stash_address);
        let server_info = query_chain(&api, &rpc, threshold_address_query, block_hash)
            .await?
            .ok_or_else(|| ValidatorErr::ChainFetch("Cannot find sender public key"))?;
        server_info.x25519_public_key
    };

    let mut values: Vec<EncryptedSignedMessage> = vec![];
    for key in keys.keys {
        check_forbidden_key(&key)?;
        let result = app_state.kv_store.kv().get(&key).await?;
        let reencrypted_key_result =
            EncryptedSignedMessage::new(signer.signer(), result, &sender_encryption_pk, &[])
                .map_err(|e| ValidatorErr::Encryption(e.to_string()))?;
        values.push(reencrypted_key_result)
    }
    Ok(Json(Values { values }))
}

/// As a node is joining the network should get all keys that are registered
/// This is done by reading the registered mapping and getting all the keys of that mapping
pub async fn get_all_keys(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<String>, ValidatorErr> {
    let mut addresses: Vec<String> = vec![];
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Error getting block hash"))?;
    // query the registered mapping in the registry pallet
    let storage_address = entropy::storage().registry().registered_iter();
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    while let Some(Ok(kv)) = iter.next().await {
        let new_key = hex::encode(kv.key_bytes);
        let len = new_key.len();
        let final_key = &new_key[len - (VERIFICATION_KEY_LENGTH as usize * 2)..];
        // checks address is valid
        addresses.push(final_key.to_string())
    }
    Ok(addresses)
}

/// Returns a random server from a given sub-group.
pub async fn get_random_server_info(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    my_subgroup: u8,
    my_stash_address: subxt::utils::AccountId32,
) -> Result<ServerInfo<subxt::utils::AccountId32>, ValidatorErr> {
    let block_hash = rpc.chain_get_block_hash(None).await?;
    let signing_group_addresses_query =
        entropy::storage().staking_extension().signing_groups(my_subgroup);
    let signing_group_addresses = query_chain(api, rpc, signing_group_addresses_query, block_hash)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Querying Signing Groups Error"))?;
    // TODO: Just gets first person in subgroup, maybe do this randomly?
    // find kvdb that isn't syncing and get their URL
    let mut server_to_query = 0;
    let server_info = loop {
        let address_to_query = signing_group_addresses
            .get(server_to_query)
            .ok_or(ValidatorErr::SubgroupError("Index out of bounds"))?;
        let server_info_query =
            entropy::storage().staking_extension().threshold_servers(address_to_query);
        let server_info = query_chain(api, rpc, server_info_query, block_hash)
            .await?
            .ok_or_else(|| ValidatorErr::ChainFetch("Server Info Fetch Error"))?;
        let server_state_query =
            entropy::storage().staking_extension().is_validator_synced(address_to_query);
        let server_sync_state = query_chain(api, rpc, server_state_query, block_hash)
            .await?
            .ok_or_else(|| ValidatorErr::ChainFetch("Server State Fetch Error"))?;
        if &my_stash_address != address_to_query && server_sync_state {
            break server_info;
        }
        server_to_query += 1;
    };

    Ok(server_info)
}

/// From keys of registered accounts get their corresponding entropy threshold keys
pub async fn get_and_store_values(
    all_keys: Vec<String>,
    kv: &KvManager,
    batch_size: usize,
    dev: bool,
    recip_server_info: ServerInfo<subxt::utils::AccountId32>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    x25519_secret: &StaticSecret,
) -> Result<(), ValidatorErr> {
    let url = String::from_utf8(recip_server_info.endpoint)?;
    let mut keys_stored = 0;
    while keys_stored < all_keys.len() {
        let mut keys_to_send_slice = batch_size + keys_stored;
        if keys_to_send_slice > all_keys.len() {
            keys_to_send_slice = all_keys.len();
        }
        let remaining_keys = all_keys[keys_stored..(keys_to_send_slice)].to_vec();
        let keys_to_send = Keys { keys: remaining_keys.clone(), timestamp: SystemTime::now() };
        let enc_keys = EncryptedSignedMessage::new(
            signer.signer(),
            serde_json::to_vec(&keys_to_send)?,
            &recip_server_info.x25519_public_key,
            &[],
        )
        .map_err(|e| ValidatorErr::Decryption(e.to_string()))?;
        let client = reqwest::Client::new();
        let formatted_url = format!("http://{url}/validator/sync_kvdb");
        let result = client
            .post(formatted_url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&enc_keys)?)
            .send()
            .await?;

        if result.status() == 500 && dev {
            keys_stored += 1;
            continue;
        }
        // handle no value better? or don't maybe good to fail
        let returned_values: Values = result.json().await?;
        if returned_values.values.is_empty() {
            break;
        }
        for (i, encrypted_key) in returned_values.values.iter().enumerate() {
            // if it exists could be old, delete old key grab new one
            if kv.kv().exists(&remaining_keys[i].clone()).await? {
                kv.kv().delete(&remaining_keys[i].clone()).await?;
            }

            let reservation = kv.kv().reserve_key(remaining_keys[i].clone()).await?;
            let key = {
                let signed_message = encrypted_key
                    .decrypt(x25519_secret, &[])
                    .map_err(|e| ValidatorErr::Decryption(e.to_string()))?;
                if signed_message.sender.0 != recip_server_info.tss_account.0 {
                    return Err(ValidatorErr::Authentication);
                };
                signed_message.message.0
            };
            kv.kv().put(reservation, key).await?;
            keys_stored += 1
        }
    }
    Ok(())
}
/// Sends a transaction telling the chain it is fully synced
pub async fn tell_chain_syncing_is_done(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, subxt::ext::sp_core::sr25519::Pair>,
) -> Result<(), ValidatorErr> {
    let synced_tx = entropy::tx().staking_extension().declare_synced(true);
    let _ = submit_transaction(api, rpc, signer, &synced_tx, None).await?;
    Ok(())
}

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

/// Checks to see if message sender is in the same subgroup as current validator
pub async fn check_in_subgroup(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    signing_address: &AccountId32,
) -> Result<(), ValidatorErr> {
    let signing_address = SubxtAccountId32::from_str(&signing_address.to_ss58check())
        .map_err(|_| ValidatorErr::StringError("Account Conversion"))?;

    let stash_subgroup = get_subgroup(api, rpc, &signing_address).await?;
    let signer_subgroup = get_subgroup(api, rpc, signer.account_id()).await?;

    if stash_subgroup != signer_subgroup {
        return Err(ValidatorErr::NotInSubgroup);
    }

    Ok(())
}
