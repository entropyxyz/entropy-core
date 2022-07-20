#![allow(dead_code)]
#![allow(unused_imports)]
use futures::Stream;
use rocket::{
	response::stream::ByteStream,
	serde::{json::Json, Deserialize, Serialize},
	tokio::{
		select,
		sync::broadcast::{error::RecvError, Sender},
	},
	Shutdown, State,
};
use tofnd::{gg20::types::PartyInfo, proto::SignInit};
use tokio::sync::broadcast::{self, Receiver};
use tracing::{info, instrument};

use crate::Global;

pub type PartyId = usize; // TODO(TK): this is probably somewhere else already
pub type SigningChannel = broadcast::Sender<SigningMessage>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningRegistrationMessage {
	pub party_id: PartyId,
	// pub msg: String, // TODO(TK): what else
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
	pub party_id: PartyId,
	// pub todo: String,
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
#[post("/signing_registration", data = "<new_party>")]
pub async fn signing_registration(
	new_party: Json<SigningRegistrationMessage>,
	end: Shutdown,
	state: &State<Global>,
) -> (){
// ) -> ByteStream!<> {
	// ) -> ByteStream!{Vec<u8>} {
	let new_party = new_party.into_inner();
	validate_registration(&new_party);
	let cached_state = state.inner();

	// Subscribe to the sender, creating one if it doesn't yet exist.
	let rx = subscribe_or_create_channel(cached_state, new_party.clone());

	// When a new message is broadcast, pass the message to the subscribing node.
	make_byte_stream(new_party, rx, end).await;
	// make_byte_stream(new_party, rx, end).await
	todo!()
}

fn subscribe_or_create_channel(
	cached_state: &Global,
	new_party: SigningRegistrationMessage,
) -> Receiver<SigningMessage> {
	// clone the signing channel resource separately to avoid prematurely freeing the state
	let signing_channels_mutex = cached_state.signing_channels.clone();
	let signing_channels = &mut *signing_channels_mutex.lock().unwrap();
	match signing_channels.get(&new_party.party_id) {
		None => {
			{
				// No channel exists yet, so create an effectively unbounded broadcast channel
				let (tx, rx) = broadcast::channel(1000);

				signing_channels.insert(new_party.party_id, tx);

				rx
			}
		},
		Some(tx) => tx.subscribe(),
	}
}

// TODO(TK): this is probably borked, fix it when rdy
async fn make_byte_stream(
	new_party: SigningRegistrationMessage,
	mut rx: Receiver<SigningMessage>,
	mut end: Shutdown,
) -> ByteStream<Vec<u8>> {
	todo!()
}
// ) -> ByteStream!{Vec<u8>} {
// 	ByteStream! {
// 		loop {
// 			let msg = select! {
// 				new_party = rx.recv() => match new_party {
// 					Ok(msg) => msg,
// 					Err(RecvError::Closed) => break,
// 					Err(RecvError::Lagged(_)) => continue,
// 				},
// 				_ = &mut end => break,
// 			};

// 			yield msg
// 		}
// 	}
// }

/// Sanitize argemunts to
// #[tracing::instrument]
pub(crate) async fn handle_sign(
	tx: Sender<SigningMessage>,
	rx_channels: Vec<ByteStream<Vec<u8>>>,
) -> anyhow::Result<()> {
	// info!("handle_sign");
	let (sign_init, party_info) = handle_sign_init(tx, rx_channels).await?;
	todo!();
}

// #[tracing::instrument]
async fn handle_sign_init(
	tx: Sender<SigningMessage>,
	rx_channels: Vec<ByteStream<Vec<u8>>>,
) -> anyhow::Result<(SignInit, PartyInfo)> {
	// info!("handle_sign");
	todo!()
}

/// Validate `SigningRegistrationMessage`
fn validate_registration(msg: &SigningRegistrationMessage) {
	todo!();
}
