use kvdb::kv_manager::KvManager;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use tracing::instrument;

use crate::{
  sign_init::SignInit,
  signing_client::{
    new_party::{Channels, Gg20Service},
    subscribe::{subscribe_all, Listener},
    SignerState, SigningErr, SubscribeErr, SubscribeMessage,
  },
};

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
) -> Result<Status, SigningErr> {
  let info = info.into_inner();
  info!("new_party: {info:?}");
  let gg20_service = Gg20Service::new(state, kv_manager);

  // set up context for signing protocol execution
  let sign_context = gg20_service.get_sign_context(info).await?;

  // subscribe to all other participating parties. Listener waits for other subscribers.
  let (rx_ready, listener) = Listener::new();
  state.listeners.lock().unwrap().insert(sign_context.sign_init.party_uid.to_string(), listener);
  let channels = {
    let stream_in = subscribe_all(&sign_context).await?;
    let broadcast_out = rx_ready.await??;
    Channels(stream_in, broadcast_out)
  };

  let result = gg20_service.execute_sign(&sign_context, channels).await?;
  gg20_service.handle_result(&result, &sign_context);
  Ok(Status::Ok)
}

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
) -> Result<EventStream![], SubscribeErr> {
  // todo error type
  let msg = msg.into_inner();
  info!("got subscribe, with message: {msg:?}");

  msg.validate_registration()?;

  if !state.contains_listener(&msg.party_id) {
    // todo
    // The CM hasn't yet informed this node of the party.
    // Wait for a timeout and try again, or else fail
    return Err(SubscribeErr::Timeout("CM hasn't informed this node yet"));
  }

  let rx = {
    let listener = state.listeners.lock().unwrap();
    let listener = listener.get(&msg.party_id).unwrap();
    listener.subscribe(&msg)?
  };
  Ok(Listener::create_event_stream(rx, end))
}
