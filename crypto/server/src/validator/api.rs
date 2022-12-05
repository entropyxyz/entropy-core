use std::str::FromStr;

use hex_literal::hex;
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KvManager,
};
use parity_scale_codec::Decode;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use sp_core::{crypto::AccountId32, sr25519, Pair, Public};
use subxt::OnlineClient;
use tokio::sync::{mpsc, oneshot};

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    Configuration,
};
#[post("/sync_keys", format = "json")]
pub async fn sync_keys(kv: &State<KvManager>, config: &State<Configuration>) -> Result<(), ()> {
    let api = get_api(&config.endpoint).await.unwrap();
    // dbg!(tree_names);
    // validate on chain that this user in your subgroup
    // validate the message comes from individual
    // validate the message is intended for me

    // encrypt message and send to other validator
    Ok(())
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
