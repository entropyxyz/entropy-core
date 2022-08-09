use crate::{
	signing_client::{SigningProtocolError, SubscribingMessage},
	ProtocolManager, SignerState, SubscriberManager,
};
use futures::TryFutureExt;
use non_substrate_common::{CMInfoUnchecked, KvKeyshareInfo};
// use reqwest::{self};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use tracing::instrument;
// use uuid::Uuid;

/// Initiate a new signing party.
/// Communication Manager calls this endpoint for each node in the new Signing Party.
/// The node creates a `ProtocolManager` to run the protocol, and a SubscriberManager to manage
/// subscribed nodes. This method should run the protocol, returning the result.
// TODO(TK): write new_party errors instead of panicking and unwrapping everywhere
#[instrument]
#[post("/new_party", format = "json", data = "<info>")]
pub async fn new_party(
	info: Json<CMInfoUnchecked>,
	state: &State<SignerState>,
) -> Result<Status, SigningProtocolError> {
	info!("new_party: {:?}", info);
	// TODO(TK): this should return a KvShare, not Vec<u8>, unclear why type is Vec<u8>
	// temporary hack to get around: try_into().unwrap()
	let kv_share = state
		.kv_manager
		.kv()
		.get(&info.key_uid.to_string())
		.await
		.unwrap()
		.try_into()
		.unwrap();
	let cm_info = info.into_inner().check(&kv_share).unwrap();
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
	let _outcome = protocol_manager
		.subscribe_and_await_subscribers()
		.and_then(move |subscribed_party| subscribed_party.sign())
		.await
		.unwrap()
		.get_result()
		.as_ref()
		.unwrap();

	Ok(Status::Ok)
}

/// Other nodes in the party call this method to subscribe to this node's broadcasts.
/// The SigningProtocol begins when all nodes in the party have called this method on this node.
// TODO(TK): If the CM hasn't called `new_party` on this node yet. Let the map drop, wait
// for a time-out so that CM can access the subscriber_map, and try again.
#[instrument]
#[post("/subscribe", data = "<subscribing_message>")]
pub async fn subscribe(
	subscribing_message: Json<SubscribingMessage>,
	#[allow(unused_mut)] // macro shenanigans fooling our trusty linter
	mut end: Shutdown,
	state: &State<SignerState>,
) -> EventStream![] {
	info!("signing_registration");
	let subscribing_message = subscribing_message.into_inner();
	subscribing_message.validate_registration().unwrap();

	let mut subscriber_manager_map = state.subscriber_manager_map.lock().unwrap();
	if !subscriber_manager_map.contains_key(&subscribing_message.party_id) {
		// The CM hasn't yet informed this node of the party. Give CM some time to provide
		// subscriber details.
	};

	let rx = subscribing_message.create_new_subscription(&mut subscriber_manager_map);
	// maybe unnecessary. Drop the subscriber map before returning to avoid blocking
	drop(subscriber_manager_map);
	subscribing_message.create_event_stream(rx, end)
}
