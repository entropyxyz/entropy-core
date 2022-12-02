use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KvManager,
};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use subxt::OnlineClient;
use tokio::sync::{mpsc, oneshot};
use sp_core::{Pair, sr25519, crypto::AccountId32, Public};
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    Configuration,
};
use hex_literal::hex;
use std::str::FromStr;
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
pub async fn get_all_keys(api: &OnlineClient<EntropyConfig>) -> Result<(), ()> {
    let storage_address = subxt::dynamic::storage_root("Relayer", "Registered");
    let mut iter = api.storage().iter(storage_address, 10, None).await.unwrap();
    dbg!("here");

    while let Some((key, account)) = iter.next().await.unwrap() {
		let new_key = hex::encode(key);
		let len = new_key.len();
		let final_key = &new_key[len-64..];
		dbg!(final_key);

		let address: AccountId32 = AccountId32::from_str(final_key).unwrap();

        dbg!(address.to_string(), account.to_value().unwrap());
    }
    Ok(())
}
