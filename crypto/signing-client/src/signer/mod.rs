#![allow(dead_code)]
use rocket::{
	form::Form,
	fs::{relative, FileServer},
	futures::TryFutureExt,
	response::stream::{Event, EventStream},
	serde::{json::Json, Deserialize, Serialize},
	tokio::{
		select,
		sync::broadcast::{channel, error::RecvError, Sender},
	},
	Shutdown, State,
};
use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
	thread::spawn,
};
use tofnd::kv_manager::KvManager;
use tokio::sync::broadcast::{self, Receiver};

use crate::{ip_discovery::NewParty, Global};

pub type PartyId = usize; // TODO(TK): this is probably somewhere else already
pub type SigningChannel = broadcast::Sender<SigningMessage>;

#[derive(Debug, Clone, FromForm, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningRegistrationMessage {
	pub party_id: PartyId,
	// pub msg: String, // TODO(TK): what else
}

#[derive(Debug, Clone, FromForm, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
	pub party_id: PartyId,
	// pub todo: String,
}

/// After receiving the ip addresses of the signing party (`post_new_party_ips`), each participating node
/// in the signing-protocol calls this method on each other node, "registering" themselves for the
/// signing procedure. Calling `signing_registration` subscribes the caller to the stream of
/// messages related to this execution of the signing protocol.
///
///  Arguments:
/// - `form`: arguments for registration (todo)
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
#[post("/signing_registration", data = "<form>")]
pub async fn signing_registration(
	form: Form<SigningRegistrationMessage>,
	mut end: Shutdown,
	state: &State<Global>,
) -> EventStream![] {
	let msg = form.into_inner();
	validate_registration(&msg);
	// TODO(TK): flatten cached state let bindings
	let cached_state = state.inner();

	// TODO(TK): move to helper
	// Subscribe to the sender, creating one if it doesn't yet exist.
	let mut rx = {
		// clone the signing channel resource separately to avoid prematurely freeing the state
		let signing_channels_mutex = cached_state.signing_channels.clone();
		let signing_channels = &mut *signing_channels_mutex.lock().unwrap();
		match signing_channels.get(&msg.party_id) {
			None => {
				{
					// No channel exists yet, so create an effectively unbounded broadcast channel
					let (tx, rx) = broadcast::channel(1000);

					signing_channels.insert(msg.party_id, tx);

					rx
				}
			},
			Some(tx) => tx.subscribe(),
		}
	};

	// TODO(TK): move to helper
	// When a new message is broadcast, pass the message to the subscribing node.
	EventStream! {
		loop {
			let msg = select! {
				msg = rx.recv() => match msg {
					Ok(msg) => msg,
					Err(RecvError::Closed) => break,
					Err(RecvError::Lagged(_)) => continue,
				},
				_ = &mut end => break,
			};

			yield Event::json(&msg);
		}
	}
}

async fn all_ready() -> bool {
	todo!();
}

/// Validate `SigningRegistrationMessage`
fn validate_registration(msg: &SigningRegistrationMessage) {
	todo!();
}

/// Initiate the signing process.
async fn handle_signing_init(tx: &Sender<SigningMessage>) {
	todo!();
}

/// wrapping interface to tofn signing-protocol.
async fn handle_signing(tx: Sender<SigningMessage>) {
	todo!();
}
