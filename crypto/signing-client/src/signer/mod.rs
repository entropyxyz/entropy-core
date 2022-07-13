use rocket::{
	form::Form,
	fs::{relative, FileServer},
	futures::TryFutureExt,
	response::stream::{Event, EventStream},
	serde::{Deserialize, Serialize},
	tokio::{
		select,
		sync::broadcast::{channel, error::RecvError, Sender},
	},
	Shutdown, State,
};
use std::{collections::HashMap, sync::Mutex, thread::spawn};
use tofnd::kv_manager::KvManager;
use tokio::sync::broadcast::{self, Receiver};

pub type PartyId = usize; // TODO(TK): this is probably somewhere else already
pub type SigningChannel = broadcast::Sender<SigningMessage>;

#[derive(Debug, Clone, FromForm, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningRegistrationMessage {
	pub party_id: PartyId,
	// pub todo: String,
}

#[derive(Debug, Clone, FromForm, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
	pub party_id: PartyId,
	// pub todo: String,
}

/// Each participating node in the signing-protocol calls this method on each other node,
/// "registering" themselves for the signing procedure. Calling `signing_registration` subscribes
/// the caller to the stream of messages related to this execution of the signing protocol. This
/// node will call this method on each other node in the signing protocol. Each
/// `SigningRegistrationMessage` contains:
/// - todo
///
/// Alternative implementation: Suppose this node can trust a single description of the Signing
/// Party (communication manager style). Then only one call of this method (by the CM) would be
/// required, informing this node of the signing party.
///
/// Todo:
/// - Handle timeout failure: if any node does not touch `init_signing_message`,
/// - Test: reject conflicting signing parties
/// - Test: reject double registration
/// - Test: must fail if party is over
/// - Test: must not fail if messages are out of order
/// - Note: do we authenticate who sends message here or in tofn?
#[post("/signing_registration", data = "<form>")]
pub async fn signing_registration(
	form: Form<SigningRegistrationMessage>,
	mut end: Shutdown,
	signing_channels: &State<Mutex<HashMap<PartyId, SigningChannel>>>, /* todo: ask jesse more
	                                                                    * about this */
	kv_manager: &State<Mutex<KvManager>>, // todo: ask jesse more about this
) -> EventStream![] {
	let msg = form.into_inner();
	// If this node does not know about a signing party corresponding to this SigningRegistration,
	// create one. Spawn a thread to subscribe to all other nodes, in the party and execute the
	// protocol. TODO(TK): do something more robust than unwrapping the lock
	let mut rx = match signing_channels.lock().unwrap().get(&msg.party_id) {
		None => {
			{
				// create an effectively unbounded broadcast channel
				let (tx, rx) = broadcast::channel(1000);

				//
				// `handle_signing`
				// let _signing_init_handle = spawn(|| handle_signing_init(tx));
				rx
			}
		},
		Some(tx) => {
			validate_registration(&msg);
			tx.subscribe()
		},
	};

	// Pass messages produced by this node to subscribers. See `handle_signing`.
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

/// Validate `SigningRegistrationMessage`
fn validate_registration(msg: &SigningRegistrationMessage) {
	todo!();
}

/// Subscribe to all other nodes in the signing party.
async fn handle_signing_init(tx: Sender<SigningMessage>) {
	todo!();
}

/// wrapping interface to tofn signing-protocol.
async fn handle_signing(tx: Sender<SigningMessage>) {
	todo!();
}
