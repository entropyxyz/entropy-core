use std::str::FromStr;

use axum::{
    extract::State,
    Json,
};
use kvdb::kv_manager::KvManager;
use reqwest;
use serde::{Deserialize, Serialize};
use sp_core::{crypto::AccountId32, sr25519, Bytes};
use subxt::{tx::PairSigner, OnlineClient};
use x25519_dalek::PublicKey;

use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_staking_extension::pallet::ServerInfo},
        EntropyConfig,
    },
    get_signer,
    validation::SignedMessage,
    validator::errors::ValidatorErr,
    AppState,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Keys {
    pub enckeys: Vec<SignedMessage>,
    pub sender: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Values {
    pub values: Vec<SignedMessage>,
}

/// Endpoint to allow a new node to sync their kvdb with a member of their subgroup
pub async fn sync_kvdb(
    State(app_state): State<AppState>,
    Json(keys): Json<Keys>,
) -> Result<Json<Values>, ValidatorErr> {
    // TODO(JS): validate on chain that this user in your subgroup
    let sender = PublicKey::from(keys.sender);
    let signer = get_signer(&app_state.kv_store).await?;
    let recip_secret_key = signer.signer();
    let mut values: Vec<SignedMessage> = vec![];
    for encrypted_key in keys.enckeys.clone() {
        if !encrypted_key.verify() {
            return Err(ValidatorErr::SafeCryptoError("Invalid signature."));
        }
        let dmsg = encrypted_key.decrypt(recip_secret_key);
        if dmsg.is_err() {
            return Err(ValidatorErr::SafeCryptoError("Decryption failed."));
        }
        let key = dmsg.map_err(|e| ValidatorErr::Decryption(e.to_string()))?;
        // encrypt message and send to other validator
        let skey = String::from_utf8_lossy(&key).to_string();
        let result = app_state.kv_store.kv().get(skey.as_str()).await?;
        let reencrypted_key_result = SignedMessage::new(recip_secret_key, &Bytes(result), &sender)
            .map_err(|e| ValidatorErr::Encryption(e.to_string()))?;
        values.push(reencrypted_key_result)
    }
    Ok(Json(Values { values }))
}

/// As a node is joining the network should get all keys that are registered
/// This is done by reading the registered mapping and getting all the keys of that mapping
pub async fn get_all_keys(
    api: &OnlineClient<EntropyConfig>,
    batch_size: usize,
) -> Result<Vec<String>, ValidatorErr> {
    // zero batch size will cause infinite loop, also not needed
    assert_ne!(batch_size, 0);
    let mut result_length = batch_size;
    let mut addresses: Vec<String> = vec![];
    while result_length == batch_size {
        result_length = 0;
        // query the registered mapping in the relayer pallet
        let storage_address = subxt::dynamic::storage_root("Relayer", "Registered");
        let mut iter = api.storage().iter(storage_address, batch_size as u32, None).await?;
        while let Some((key, _account)) = iter.next().await? {
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
    my_subgroup: u8,
) -> Result<ServerInfo<AccountId32>, ValidatorErr> {
    let signing_group_addresses_query =
        entropy::storage().staking_extension().signing_groups(my_subgroup);
    let signing_group_addresses = api
        .storage()
        .fetch(&signing_group_addresses_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Querying Signing Groups Error"))?;

    // TODO: Just gets first person in subgroup, maybe do this randomly?
    // find kvdb that isn't syncing and get their URL
    let mut server_sync_state = false;
    let mut server_to_query = 0;
    let mut server_info: Option<
        entropy::runtime_types::pallet_staking_extension::pallet::ServerInfo<
            sp_core::crypto::AccountId32,
        >,
    > = None;
    while !server_sync_state {
        let server_info_query = entropy::storage()
            .staking_extension()
            .threshold_servers(&signing_group_addresses[server_to_query]);
        server_info = Some(
            api.storage()
                .fetch(&server_info_query, None)
                .await?
                .ok_or_else(|| ValidatorErr::OptionUnwrapError("Server Info Fetch Error"))?,
        );
        let server_state_query = entropy::storage()
            .staking_extension()
            .is_validator_synced(&signing_group_addresses[server_to_query]);
        server_sync_state = api
            .storage()
            .fetch(&server_state_query, None)
            .await?
            .ok_or_else(|| ValidatorErr::OptionUnwrapError("Server State Fetch Error"))?;
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
) -> Result<(), ValidatorErr> {
    let mut keys_stored = 0;
    while keys_stored < all_keys.len() {
        let mut keys_to_send_slice = batch_size + keys_stored;
        if keys_to_send_slice > all_keys.len() {
            keys_to_send_slice = all_keys.len();
        }
        let signer = get_signer(kv).await?;
        let remaining_keys = all_keys[keys_stored..(keys_to_send_slice)].to_vec();
        let mut enckeys: Vec<SignedMessage> = vec![];
        let mut sender: [u8; 32] = [0; 32];
        for _key in &remaining_keys {
            let new_msg =
                SignedMessage::new(signer.signer(), &Bytes(_key.clone().into_bytes()), recip)
                    .map_err(|e| ValidatorErr::Decryption(e.to_string()))?;
            sender = new_msg.sender().to_bytes();
            enckeys.push(new_msg);
        }
        let keys_to_send = Keys { enckeys, sender };
        let client = reqwest::Client::new();
        let formatted_url = format!("http://{url}/validator/sync_kvdb");
        let result = client
            .post(formatted_url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&keys_to_send)?)
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
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
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
    address: &AccountId32,
    min_balance: u128,
) -> Result<bool, ValidatorErr> {
    let balance_query = entropy::storage().system().account(address);
    let account_info =
        api.storage().fetch(&balance_query, None).await?.ok_or_else(|| {
            ValidatorErr::OptionUnwrapError("Account does not exist, add balance")
        })?;
    let balance = account_info.data.free;
    let mut is_min_balance = false;
    if balance >= min_balance {
        is_min_balance = true
    };
    Ok(is_min_balance)
}
