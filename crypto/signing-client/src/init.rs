use crate::{
	errors::SigningProtocolError, // , SIGNING_PARTY_SIZE,
	Global,
	{ProtocolManager, SubscriberManager},
};
use common::{CMInfoUnchecked, KvKeyshareInfo};
use futures::TryFutureExt;
// use reqwest::{self};
use rocket::{http::Status, serde::json::Json, State};
use tracing::instrument;
// use uuid::Uuid;

/// Initiate a new signing party.
/// Communication Manager calls this endpoint for each node in the new Signing Party.
/// The node creates a `ProtocolManager` to run the protocol, and a SubscriberManager to manage
/// subscribed nodes. This method should run the protocol, returning the result.
#[instrument]
#[post("/new_party", format = "json", data = "<info>")]
pub async fn new_party(
	info: Json<CMInfoUnchecked>,
	state: &State<Global>,
) -> Result<Status, SigningProtocolError> {
	info!("new_party");
	let stored_info: KvKeyshareInfo =
		match state.kv_manager.kv().get(&info.key_uid.to_string()).await {
			Ok(v) => v.try_into().unwrap(),
			Err(e) => panic!(), // todo
		};
	let cm_info = info.into_inner().check(&stored_info).unwrap();
	let (finalized_subscribing_tx, protocol_manager) = ProtocolManager::new(cm_info);
	{
		// store subscriber manager in state, first checking that the party_id is new
		let map = &mut *state.subscriber_manager_map.lock().unwrap();
		if map.contains_key(&protocol_manager.cm_info.party_uid) {
			return Err(SigningProtocolError::Other("re-used party_id"))
		}
		let subscriber_manager = SubscriberManager::new(finalized_subscribing_tx);
		map.insert(protocol_manager.cm_info.party_uid, Some(subscriber_manager));
	}

	// Run the protocol.
	// Todo: Should I spawn a task?
	let _outcome = protocol_manager
		.subscribe_and_await_subscribers()
		.and_then(move |subscribed_party| subscribed_party.sign())
		.await
		.unwrap()
		.get_result()
		.as_ref()
		.unwrap(); // todo: better error handling

	Ok(Status::Ok)
}
