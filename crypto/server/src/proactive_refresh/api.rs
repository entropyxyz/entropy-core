use std::str;

use blake2::{Blake2s256, Digest};
use entropy_shared::RefreshMessages;
use kvdb::kv_manager::KvManager;
use parity_scale_codec::{Decode, Encode};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use subxt::OnlineClient;
use tracing::instrument;
use sp_core::crypto::AccountId32;

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    helpers::validator::get_signer,
    Configuration,
	proactive_refresh::errors::RefreshErr
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Keys {
    pub keys: Vec<String>,
    pub values: Vec<String>,
}

// TODO error handling

#[post("/proactive_refresh", data = "<encoded_data>")]
pub async fn refresh(
    encoded_data: Vec<u8>,
    kv: &State<KvManager>,
    config: &State<Configuration>,
) -> Result<Status, RefreshErr> {
	let data = RefreshMessages::decode(&mut encoded_data.as_ref()).unwrap();
	let node_account = get_signer(&kv).await.unwrap();
	let participating = is_node_in_request(node_account.account_id(), &data).unwrap();
	if !participating {
		return Ok(Status::ImUsed)
	}
	// let api = get_api(&config.endpoint).await.unwrap();
	// validate_proactive_refresh(&api, &data).await.unwrap();

	Ok(Status::Ok)
}

#[post("/accept_refresh", data = "<encoded_data>")]
pub async fn accept_refresh(
    data: Json<Keys>,
    kv: &State<KvManager>,
    config: &State<Configuration>,
) -> Result<Status, RefreshErr> {
	// TODO validate
	// checks if in subgroup
	// checks validity of keys
	// replaces key in kvdb
}

pub fn do_proactive_refresh(data: &RefreshMessages ,kv: &State<KvManager>,) -> Result<(), ()> {
	// does proactive refresh
	// gets participants in subgroup
	// handles if a node is offline
	// sends keys to people in subgroup
}

pub async fn validate_proactive_refresh(api: &OnlineClient<EntropyConfig>, data: &RefreshMessages) -> Result<(), ()> {
	// checks current counter
	// makes sure is within current counter
	// checks kvdb for last proactive refresh done is not same as counter
	// stores last proactive refresh in kvdb
	Ok(())
}


pub fn is_node_in_request(node_address: &AccountId32, data: &RefreshMessages) -> Result<bool, ()> {
	let validator_addresses = data.iter().map(|refresh_message| {
		let converted_address = refresh_message.validator_account.clone().try_into().unwrap();
		AccountId32::new(converted_address)
	}).collect::<Vec<AccountId32>>();

	if !validator_addresses.contains(node_address) {
		return Ok(false)
	}
	Ok(true)
}
