use std::str;

use blake2::{Blake2s256, Digest};
use entropy_shared::RefreshMessages;
use kvdb::kv_manager::KvManager;
use parity_scale_codec::{Decode, Encode};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use subxt::OnlineClient;
use tracing::instrument;

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    helpers::signing::SignatureState,
    Configuration,
	proactive_refresh::errors::RefreshErr
};

#[post("/proactive_refresh", data = "<encoded_data>")]
pub async fn refresh(
    encoded_data: Vec<u8>,
    kv: &State<KvManager>,
    config: &State<Configuration>,
) -> Result<Status, RefreshErr> {
	let data = RefreshMessages::decode(&mut encoded_data.as_ref());
	Ok(Status::Ok)
}


pub fn validate_proactive_refresh() {

}


pub fn is_node_in_request() {

}
