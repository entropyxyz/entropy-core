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

#[post("/proactive_refresh", data = "<encoded_data>")]
pub async fn refresh(
    encoded_data: Vec<u8>,
    kv: &State<KvManager>,
    config: &State<Configuration>,
) -> Result<Status, RefreshErr> {
	let data = RefreshMessages::decode(&mut encoded_data.as_ref()).unwrap();
	let node_account = get_signer(&kv).await.unwrap();
	is_node_in_request(node_account.account_id(), &data).unwrap();
	Ok(Status::Ok)
}


pub fn validate_proactive_refresh() {

}


pub fn is_node_in_request(node_address: &AccountId32, data: &RefreshMessages) -> Result<(), ()> {
	let validator_addresses = data.iter().map(|refresh_message| {
		let converted_address = refresh_message.validator_account.clone().try_into().expect("slice with incorrect length");
		AccountId32::new(converted_address)
	}).collect::<Vec<AccountId32>>();

	if !validator_addresses.contains(node_address) {
		return Err(())
	}
	Ok(())
}
