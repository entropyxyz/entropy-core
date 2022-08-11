use futures::TryFutureExt;
use kvdb::kv_manager::KvManager;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use tracing::instrument;

use super::{
  new_party::Gg20Service,
  // new_user::{UserKvEntry, UserKvEntryUnparsed},
  SignerState,
  SigningProtocolError,
  SubscribeMessage,
  SubscriberManager,
};
use crate::signing_client::{new_party::SignInit, SubscribeError};
// use uuid::Uuid;

/// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/mod.rs#L39
/// Endpoint for Communication Manager to initiate a new signing party.
/// We have to do some extra work setting up subscriber streams.
///
/// Communication Manager calls this endpoint for each node in the new Signing Party.
/// The node creates a `ProtocolManager` to run the protocol, and a SubscriberManager to manage
/// subscribed nodes. This method should run the protocol, returning the result.
#[instrument(skip(kv_manager))]
#[post("/new_party", format = "json", data = "<info>")]
pub async fn new_party(
  info: Json<SignInit>,
  state: &State<SignerState>,
  kv_manager: &State<KvManager>,
) -> Result<Status, SigningProtocolError> {
  let info = info.into_inner();
  info!("new_party: {info:?}");
  let gg20_service = Gg20Service::new(state, kv_manager);

  // set up context for signing protocol execution
  let sign_context = gg20_service.get_sign_context(info).await?;

  // subscribe to all other participating parties
  let channels = gg20_service.subscribe_and_await_subscribers(&sign_context).await?;

  let result = gg20_service.execute_sign(&sign_context, channels).await?;
  gg20_service.handle_result(&result, &sign_context);
  Ok(Status::Ok)
}

// Create streams
//
// let msg_streams = SigningMessageStreams::new(tx,rx);
// let (sign_init, party_info) = gg20_service.handle_sign_init();
// TODO(TK): this should return a KvShare, not Vec<u8>, unclear why type is Vec<u8>
// temporary hack to get around: try_into().unwrap()

// let kv_share =
//   state.kv_manager.kv().get(&info.key_uid.to_string()).await.unwrap().try_into().unwrap();
// let cm_info = info.into_inner().check(&kv_share).unwrap();
// let (finalized_subscribing_tx, protocol_manager) = ProtocolManager::new(cm_info);
// {
//   // store subscriber manager in state, first checking that the party_id is new
//   let map = &mut *state.subscriber_manager_map.lock().unwrap();
//   if map.contains_key(&protocol_manager.cm_info.party_uid) {
//     return Err(SigningProtocolError::Other("re-used party_id"));
//   }
//   let subscriber_manager = SubscriberManager::new(finalized_subscribing_tx);
//   map.insert(protocol_manager.cm_info.party_uid, Some(subscriber_manager));
// }

// // Run the protocol.
// let _outcome = protocol_manager
//   .subscribe_and_await_subscribers()
//   .and_then(move |subscribed_party| subscribed_party.sign())
//   .await
//   .unwrap()
//   .get_result()
//   .as_ref()
//   .unwrap();

/// Other nodes in the party call this method to subscribe to this node's broadcasts.
/// The SigningProtocol begins when all nodes in the party have called this method on this node.
// TODO(TK): If the CM hasn't called `new_party` on this node yet. Let the map drop, wait
// for a time-out so that CM can access the subscriber_map, and try again.
#[instrument]
#[post("/subscribe", data = "<msg>")]
pub async fn subscribe(
  msg: Json<SubscribeMessage>,
  #[allow(unused_mut)] // macro shenanigans fooling our trusty linter
  mut end: Shutdown,
  state: &State<SignerState>,
) -> Result<EventStream![], SubscribeError> {
  // todo error type
  let msg = msg.into_inner();
  info!("got subscribe, with message: {msg:?}");
  msg.validate_registration().unwrap();

  let mut subscriber_manager_map = state.subscriber_manager_map.lock().unwrap();
  if !subscriber_manager_map.contains_key(&msg.party_id) {
    // The CM hasn't yet informed this node of the party. Give CM some time to provide
    // subscriber details.
  };

  let rx = msg.create_new_subscription(&mut subscriber_manager_map);
  // maybe unnecessary. Drop the subscriber map before returning to avoid blocking
  drop(subscriber_manager_map);
  Ok(SubscribeMessage::create_event_stream(rx, end))
}
