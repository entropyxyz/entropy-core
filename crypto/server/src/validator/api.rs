use std::{str::FromStr, time::SystemTime};

use axum::{extract::State, Json};
use kvdb::kv_manager::KvManager;
use reqwest;
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    ext::sp_core::{sr25519, Bytes},
    tx::PairSigner,
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
        substrate::{get_subgroup, return_all_addresses_of_subgroup},
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

/// Endpoint to allow a new node to sync their kvdb with a member of their subgroup
pub async fn sync_kvdb(
    State(app_state): State<AppState>,
    Json(signed_msg): Json<SignedMessage>,
) -> Result<Json<Values>, ValidatorErr> {
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await.unwrap();

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
    batch_size: usize,
) -> Result<Vec<String>, ValidatorErr> {
    // TODO: get all keys should return all keys not just "batch size"
    // zero batch size will cause infinite loop, also not needed
    assert_ne!(batch_size, 0);
    let mut result_length = batch_size;
    let mut addresses: Vec<String> = vec![];
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or_else(|| ValidatorErr::OptionUnwrapError("Errir getting block hash"))?;
    while result_length == batch_size {
        result_length = 0;
        // query the registered mapping in the relayer pallet
        let keys = Vec::<()>::new();
        let storage_address = subxt::dynamic::storage("Relayer", "Registered", keys);
        let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
        while let Some(Ok((key, _account))) = iter.next().await {
            let new_key = hex::encode(key);
            let len = new_key.len();
            let final_key = &new_key[len - 64..];

            let address: AccountId32 =
                AccountId32::from_str(final_key).expect("Account conversion error");

            // todo add validation
            // dbg!(address.to_string(), bool::decode(mut account));
            // if account.to_value()? {
            if addresses.contains(&address.to_string()) {
                result_length = 0;
            } else {
                addresses.push(address.to_string());
                result_length += 1;
            }
        }
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
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or_else(|| ValidatorErr::OptionUnwrapError("Errir getting block hash"))?;
    let signing_group_addresses = api
        .storage()
        .at(block_hash)
        .fetch(&signing_group_addresses_query)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Querying Signing Groups Error"))?;
    // TODO: Just gets first person in subgroup, maybe do this randomly?
    // find kvdb that isn't syncing and get their URL
    let mut server_sync_state = false;
    let mut not_me = true;
    let mut server_to_query = 0;
    let mut server_info: Option<
        entropy::runtime_types::pallet_staking_extension::pallet::ServerInfo<
            subxt::utils::AccountId32,
        >,
    > = None;
    while !server_sync_state || !not_me {
        let server_info_query = entropy::storage()
            .staking_extension()
            .threshold_servers(&signing_group_addresses[server_to_query]);
        server_info = Some(
            api.storage()
                .at(block_hash)
                .fetch(&server_info_query)
                .await?
                .ok_or_else(|| ValidatorErr::OptionUnwrapError("Server Info Fetch Error"))?,
        );
        let server_state_query = entropy::storage()
            .staking_extension()
            .is_validator_synced(&signing_group_addresses[server_to_query]);
        server_sync_state = api
            .storage()
            .at(block_hash)
            .fetch(&server_state_query)
            .await?
            .ok_or_else(|| ValidatorErr::OptionUnwrapError("Server State Fetch Error"))?;
        if my_stash_address == signing_group_addresses[server_to_query] {
            not_me = false
        }
        server_to_query += 1;
    }
    let server_info_result =
        server_info.ok_or_else(|| ValidatorErr::OptionUnwrapError("Server State Fetch Error"))?;
    Ok(server_info_result)
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
    signer: &PairSigner<EntropyConfig, subxt::ext::sp_core::sr25519::Pair>,
) -> Result<(), ValidatorErr> {
    let synced_tx = entropy::tx().staking_extension().declare_synced(true);
    let _ = api
        .tx()
        .sign_and_submit_then_watch_default(&synced_tx, signer)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
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
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or_else(|| ValidatorErr::OptionUnwrapError("Errir getting block hash"))?;
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
    let addresses_in_subgroup = return_all_addresses_of_subgroup(api, &rpc, my_subgroup).await?;
    let signing_address_converted = SubxtAccountId32::from_str(&signing_address.to_ss58check())
        .map_err(|_| ValidatorErr::StringError("Account Conversion"))?;
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(signing_address_converted);
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or_else(|| ValidatorErr::OptionUnwrapError("Errir getting block hash"))?;

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
