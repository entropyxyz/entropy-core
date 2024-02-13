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
use entropy_shared::MIN_BALANCE;
use reqwest;
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::{str::FromStr, thread, time::Duration, time::SystemTime};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    ext::sp_core::{sr25519, Bytes},
    tx::{PairSigner, TxPayload},
    utils::AccountId32 as SubxtAccountId32,
    OnlineClient,
};
use x25519_dalek::PublicKey;

use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_staking_extension::pallet::ServerInfo},
        get_api, get_rpc, EntropyConfig,
    },
    get_signer,
    helpers::{
        launch::FORBIDDEN_KEYS,
        substrate::{get_subgroup, return_all_addresses_of_subgroup, send_tx},
    },
    validation::{check_stale, SignedMessage},
    validator::errors::ValidatorErr,
    AppState,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Keys {
    pub keys: Vec<String>,
    pub timestamp: SystemTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Values {
    pub values: Vec<SignedMessage>,
}

// TODO: find a proper batch size
pub const BATHC_SIZE_FOR_KEY_VALUE_GET: usize = 10;

/// Syncs a validator by:
/// - getting all registered keys from chain
/// - finding a server in their subgroup that is synced
/// - getting all shards from said validator
#[tracing::instrument(skip(kv_store))]
pub async fn sync_validator(sync: bool, dev: bool, endpoint: &str, kv_store: &KvManager) {
    if sync {
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
        let signer = get_signer(kv_store).await.expect("Issue acquiring threshold signer key");
        let has_fee_balance = check_balance_for_fees(&api, &rpc, signer.account_id(), MIN_BALANCE)
            .await
            .expect("Issue checking chain for signer balance");
        if !has_fee_balance {
            panic!("threshold account needs balance: {:?}", signer.account_id());
        }
        // if not in subgroup retry until you are
        let mut my_subgroup = get_subgroup(&api, &rpc, &signer).await;
        while my_subgroup.is_err() {
            tracing::warn!("The signing account is not in the validator set, retrying sync");
            thread::sleep(sleep_time);
            my_subgroup =
                Ok(get_subgroup(&api, &rpc, &signer).await.expect("Failed to get subgroup."));
        }
        let (subgroup, validator_stash) = my_subgroup.expect("Failed to get subgroup.");
        let key_server_info = get_random_server_info(
            &api,
            &rpc,
            subgroup.expect("failed to get subgroup"),
            validator_stash,
        )
        .await
        .expect("Issue getting registered keys from chain.");
        let ip_address =
            String::from_utf8(key_server_info.endpoint).expect("failed to parse IP address.");
        let recip_key = x25519_dalek::PublicKey::from(key_server_info.x25519_public_key);
        let all_keys = get_all_keys(&api, &rpc).await.expect("failed to get all keys.");
        get_and_store_values(
            all_keys,
            kv_store,
            ip_address,
            BATHC_SIZE_FOR_KEY_VALUE_GET,
            dev,
            &recip_key,
            &signer,
        )
        .await
        .expect("failed to get and store all values");
        tell_chain_syncing_is_done(&api, &rpc, &signer)
            .await
            .expect("failed to finish chain sync.");
    }
}

/// Endpoint to allow a new node to sync their kvdb with a member of their subgroup
#[tracing::instrument(skip_all, fields(signing_address = %signed_msg.account_id()))]
pub async fn sync_kvdb(
    State(app_state): State<AppState>,
    Json(signed_msg): Json<SignedMessage>,
) -> Result<Json<Values>, ValidatorErr> {
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    let signing_address = signed_msg.account_id();
    if !signed_msg.verify() {
        return Err(ValidatorErr::InvalidSignature("Invalid signature."));
    }
    let sender = PublicKey::from(signed_msg.sender().to_bytes());
    let signer = get_signer(&app_state.kv_store).await?;
    let decrypted_message = signed_msg.decrypt(signer.signer())?;
    let keys: Keys = serde_json::from_slice(&decrypted_message)?;
    check_stale(keys.timestamp)?;
    check_in_subgroup(&api, &rpc, &signer, signing_address).await?;

    let mut values: Vec<SignedMessage> = vec![];
    for key in keys.keys {
        check_forbidden_key(&key)?;
        let result = app_state.kv_store.kv().get(&key).await?;
        let reencrypted_key_result = SignedMessage::new(signer.signer(), &Bytes(result), &sender)
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
    // query the registered mapping in the relayer pallet
    let keys = Vec::<()>::new();
    let storage_address = subxt::dynamic::storage("Relayer", "Registered", keys);
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    while let Some(Ok((key, _account))) = iter.next().await {
        let new_key = hex::encode(key);
        let len = new_key.len();
        let final_key = &new_key[len - 64..];
        // checks address is valid
        let address: AccountId32 = AccountId32::from_str(final_key)
            .map_err(|_| ValidatorErr::AddressConversionError("Invalid Address".to_string()))?;
        addresses.push(address.to_string())
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
    let signing_group_addresses_query =
        entropy::storage().staking_extension().signing_groups(my_subgroup);
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Error getting block hash"))?;
    let signing_group_addresses = api
        .storage()
        .at(block_hash)
        .fetch(&signing_group_addresses_query)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Querying Signing Groups Error"))?;
    // TODO: Just gets first person in subgroup, maybe do this randomly?
    // find kvdb that isn't syncing and get their URL
    let mut server_to_query = 0;
    let server_info = loop {
        let address_to_query = signing_group_addresses
            .get(server_to_query)
            .ok_or(ValidatorErr::SubgroupError("Index out of bounds"))?;
        let server_info_query =
            entropy::storage().staking_extension().threshold_servers(address_to_query);
        let server_info = api
            .storage()
            .at(block_hash)
            .fetch(&server_info_query)
            .await?
            .ok_or_else(|| ValidatorErr::OptionUnwrapError("Server Info Fetch Error"))?;
        let server_state_query =
            entropy::storage().staking_extension().is_validator_synced(address_to_query);
        let server_sync_state = api
            .storage()
            .at(block_hash)
            .fetch(&server_state_query)
            .await?
            .ok_or_else(|| ValidatorErr::OptionUnwrapError("Server State Fetch Error"))?;
        if &my_stash_address != address_to_query && server_sync_state {
            break server_info;
        }
        server_to_query += 1;
    };

    Ok(server_info)
}

/// from keys of registered account get their corresponding entropy threshold keys
pub async fn get_and_store_values(
    all_keys: Vec<String>,
    kv: &KvManager,
    url: String,
    batch_size: usize,
    dev: bool,
    recip: &x25519_dalek::PublicKey,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(), ValidatorErr> {
    let mut keys_stored = 0;
    while keys_stored < all_keys.len() {
        let mut keys_to_send_slice = batch_size + keys_stored;
        if keys_to_send_slice > all_keys.len() {
            keys_to_send_slice = all_keys.len();
        }
        let remaining_keys = all_keys[keys_stored..(keys_to_send_slice)].to_vec();
        let keys_to_send = Keys { keys: remaining_keys.clone(), timestamp: SystemTime::now() };
        let enc_keys =
            SignedMessage::new(signer.signer(), &Bytes(serde_json::to_vec(&keys_to_send)?), recip)
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
            let key = encrypted_key
                .decrypt(signer.signer())
                .map_err(|e| ValidatorErr::Decryption(e.to_string()))?;
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
    let _ = send_tx(api, rpc, signer, &synced_tx).await?;
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
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Error getting block hash"))?;
    let account_info =
        api.storage().at(block_hash).fetch(&balance_query).await?.ok_or_else(|| {
            ValidatorErr::OptionUnwrapError("Account does not exist, add balance")
        })?;
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
    signing_address: AccountId32,
) -> Result<(), ValidatorErr> {
    let (subgroup, _) = get_subgroup(api, rpc, signer).await?;
    let my_subgroup = subgroup.ok_or_else(|| ValidatorErr::SubgroupError("Subgroup Error"))?;
    let addresses_in_subgroup = return_all_addresses_of_subgroup(api, rpc, my_subgroup).await?;
    let signing_address_converted = SubxtAccountId32::from_str(&signing_address.to_ss58check())
        .map_err(|_| ValidatorErr::StringError("Account Conversion"))?;
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(signing_address_converted);
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Error getting block hash"))?;

    let stash_address = api
        .storage()
        .at(block_hash)
        .fetch(&stash_address_query)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Stash Fetch Error"))?;

    let in_subgroup = addresses_in_subgroup.contains(&stash_address);
    if !in_subgroup {
        return Err(ValidatorErr::NotInSubgroup);
    }
    Ok(())
}
