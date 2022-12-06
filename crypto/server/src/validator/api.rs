use std::str::FromStr;

use hex_literal::hex;
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KeyReservation, KvManager,
};
use parity_scale_codec::Decode;
use reqwest;
use rocket::{
    http::{ContentType, Status},
    response::{self, content, stream::EventStream, Responder, Response},
    serde::json::Json,
    Shutdown, State,
};
use serde::{Deserialize, Serialize};
use sp_core::{crypto::AccountId32, sr25519, Pair, Public};
use subxt::OnlineClient;
use tokio::sync::{mpsc, oneshot};

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    Configuration,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Keys {
    pub keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Values {
    pub values: Vec<Vec<u8>>,
}

#[post("/sync_keys", format = "json", data = "<keys>")]
pub async fn sync_keys(
    keys: Json<Keys>,
    state: &State<KvManager>,
    config: &State<Configuration>,
) -> Json<Values> {
    // let api = get_api(&config.endpoint).await.unwrap();
    // validate on chain that this user in your subgroup
    // validate the message comes from individual
    // validate the message is intended for me

    // encrypt message and send to other validator
    let mut values = vec![];
    for key in keys.keys.clone() {
        let result = state.kv().get(&key).await.unwrap();
        values.push(result);
    }
    let values_json = Values { values };
    Json(values_json)
}

/// Joining the network should get all keys that are registered
pub async fn get_all_keys(
    api: &OnlineClient<EntropyConfig>,
    batch_size: u32,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // zero batch size will cause infinite loop, also not needed
    assert_ne!(batch_size, 0);
    let mut result_length = batch_size;
    let mut addresses: Vec<String> = vec![];
    while result_length == batch_size {
        result_length = 0;
        let storage_address = subxt::dynamic::storage_root("Relayer", "Registered");
        let mut iter = api.storage().iter(storage_address, batch_size, None).await.unwrap();
        while let Some((key, account)) = iter.next().await.unwrap() {
            let new_key = hex::encode(key);
            let len = new_key.len();
            let final_key = &new_key[len - 64..];

            let address: AccountId32 = AccountId32::from_str(final_key).unwrap();

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

pub async fn get_key_url() -> Result<String, ()> {
    // get anyone in your subgroup
    // use get_subgroup from user to get your subgroup
    Ok("temp".to_string())
}

pub async fn get_and_store_keys(
    all_keys: Vec<String>,
    kv: &KvManager,
    url: String,
    batch_size: usize,
) -> Result<(), ()> {
    dbg!(all_keys.clone(), url.clone());
    let mut keys_stored = 0;
    while keys_stored < all_keys.len() {
        dbg!(keys_stored);
        let keys_to_send =
            Keys { keys: all_keys[keys_stored..(batch_size + keys_stored)].to_vec() };
        dbg!(keys_to_send.clone());
        let client = reqwest::Client::new();
        let formatted_url = format!("{}/validator/sync_keys", url);
        dbg!(formatted_url.clone());
        let result = client
            .post(formatted_url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&keys_to_send).unwrap())
            .send()
            .await
            .unwrap();
        let returned_values: Values = result.json().await.unwrap();
        dbg!(returned_values.clone());
        if returned_values.values.len() == 0 {
            break;
        }
        for (i, value) in returned_values.values.iter().enumerate() {
            dbg!(value.clone());
            let reservation = kv.kv().reserve_key(keys_to_send.keys[i].clone()).await.unwrap();
            kv.kv().put(reservation, value.to_vec()).await.unwrap();
            keys_stored += 1
        }
    }
    Ok(())
}
