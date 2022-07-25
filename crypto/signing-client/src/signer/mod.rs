#![allow(dead_code)]
#![allow(unused_imports)]
use futures::Stream;
use rocket::{
	response::stream::EventStream,
	serde::{json::Json, Deserialize, Serialize},
	tokio::{
		select,
		sync::broadcast::{error::RecvError, Sender},
	},
	Shutdown, State,
};
use tokio::sync::{
	broadcast::{self, Receiver},
	mpsc, oneshot,
};
use tracing::{info, instrument};

use crate::{Global, PartyId};

use self::context::{PartyInfo, ProtocolCommunication, SignInitSanitized};

mod context;
mod init_party_info;
mod types;
pub(crate) use init_party_info::InitPartyInfo;
pub(crate) use types::SigningParty;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SubscribingMessage {
	pub party_id: PartyId,
}

impl SubscribingMessage {
	pub(crate) fn new(party_id: PartyId) -> Self {
		Self { party_id }
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
	pub party_id: PartyId,
}

/// After receiving the ip addresses of the signing party (`new_party_ips`), each participating
/// node in the signing-protocol calls this method on each other node, "registering" themselves for
/// the signing procedure. Calling `signing_registration` subscribes the caller to the stream of
/// messages related to this execution of the signing protocol.
///
///  Arguments:
/// - `new_party`: arguments for registration (todo)
/// - `end`: shutdown signal, ends the broadcast
/// - `state`: allow signing_registration to access the `signing_channels` and `IPs` in state
///
/// Todo:
/// - Handle timeout failure?
/// - Test: reject conflicting signing parties
/// - Test: reject double registration
/// - Test: must fail if party is over
/// - Test: must not fail if messages are out of order
/// - Note: do we authenticate who sends message here or in tofn?
#[instrument]
#[post("/subscribe", data = "<subscribing_message>")]
pub async fn subscribe(
	subscribing_message: Json<SubscribingMessage>,
	end: Shutdown,
	state: &State<Global>,
) -> () {
	// ) -> EventStream!<> {
	// ) -> EventStream!{Vec<u8>} {
	info!("signing_registration");
	let new_party = subscribing_message.into_inner();
	// validate_registration(&new_party);
	// let cached_state = state.inner();

	// Subscribe to the sender, creating one if it doesn't yet exist.
	// let rx = subscribe_or_create_channel(cached_state, new_party.clone());
	todo!()
}

// #[instrument]
// fn subscribe_or_create_channel(
// 	cached_state: &Global,
// 	new_party: SubscribingMessage,
// ) -> Receiver<SigningMessage> {
// 	info!("subscribe_or_create_channel");
// 	// clone the signing channel resource separately to avoid prematurely freeing the state
// 	let signing_channels_mutex = cached_state.signing_channels.clone();
// 	let signing_channels = &mut *signing_channels_mutex.lock().unwrap();
// 	match signing_channels.get(&new_party.party_id) {
// 		None => {
// 			{
// 				// No channel exists yet, so create an effectively unbounded broadcast channel
// 				let (tx, rx) = broadcast::channel(1000);

// 				signing_channels.insert(new_party.party_id, tx);

// 				rx
// 			}
// 		},
// 		Some(tx) => tx.subscribe(),
// 	}
// }

// /// Handles initiation procedure for the signing protocol before handing off the state to
// /// `execute_sign`. 1. Unpack first message to hand to `handle_sign_init`, which sanitizes the
// /// message 2. Create a channel for communication between protocol and final result aggregator
// /// 3. Retrieve the local `Context` for the signing protocol
// /// 4. Hand off all context to `execute_sign`
// // #[instrument]
// pub(crate) async fn handle_sign(
// 	tx: Sender<SigningMessage>,
// 	rx_channels: Vec<EventStream<SigningMessage>>,
// ) -> anyhow::Result<()> {
// 	// info!("handle_sign");
// 	// TODO(TK): most of this is copy-pasted from tofnd, with adapted types. Run over it with a test
// 	// comb. 1. Unpack first message to hand to `handle_sign_init`, which sanitizes the message
// 	let (sign_init, party_info) = handle_sign_init(tx, rx_channels).await?;

// 	// 2. channel for communication between protocol and final result (seems suss)
// 	let (aggr_tx, aggr_rx): (oneshot::Sender<SigningMessage>, oneshot::Receiver<SigningMessage>) =
// 		oneshot::channel();

// 	// 3. Retrieve Context
// 	let todo_subindex = 0; // TODO(TK): placeholder
// 	let ctx = context::Context::new(sign_init.clone(), party_info.clone(), todo_subindex)?;
// 	// wrap channels needed by internal threads; receiver chan for router and sender

// 	// channels for communication between router (sender) and protocol threads (receivers)
// 	// let (sign_sender, sign_receiver) = mpsc::unbounded_channel();
// 	// let chans = ProtocolCommunication::new(sign_receiver, rx_channels.clone());

// 	// 4. Hand off all context to execute sign
// 	// let signature = execute_sign(chans, &ctx).await;
// 	// let _ = aggr_tx.send(signature);

// 	// 5. handle results

// 	Ok(())
// }

// // async fn execute_sign(chans: _, ctx: _) -> _ {
// //     todo!()
// // }

// // #[instrument]
// async fn handle_sign_init(
// 	tx: Sender<SigningMessage>, // should actually be a stream of messages in
// 	rx_channels: Vec<EventStream<SigningMessage>>,
// ) -> anyhow::Result<(SignInitSanitized, PartyInfo)> {
// 	// info!("handle_sign_init");
// 	todo!()
// }

// /// Validate `SigningRegistrationMessage`
// fn validate_registration(msg: &SubscribingMessage) {
// 	todo!();
// }
// impl SubscribingMessage {
// 	pub(crate) fn new(party_id: usize) -> Self {
// 		Self { party_id }
// 	}
// }
