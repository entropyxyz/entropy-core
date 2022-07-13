use std::collections::HashMap;

use rocket::{
	form::Form,
	fs::{relative, FileServer},
	response::stream::{Event, EventStream},
	serde::{Deserialize, Serialize},
	tokio::{
		select,
		sync::broadcast::{channel, error::RecvError, Sender},
	},
	Shutdown, State,
};

#[derive(Debug, Clone, FromForm, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningRegistrationMessage {
	pub party_id: usize,
	pub todo: String,
}

#[derive(Debug, Clone, FromForm, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
	pub todo: String,
}

/// Each participating node in the signing-protocol calls this method on each other node,
/// "registering" themselves for the signing procedure. Calling `signing_registration` subscribes
/// the caller to the stream of messages related to this execution of the signing protocol. This
/// node will also call this method on each other node in the signing protocol. Each
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
/// - Hack: currently only managing a single communication channel. Change this method to spawn new
///   communication channels in a pool, if this is the first time hearing about a signing party
/// - handle closing gracefully
#[post("/signing_registration", data = "<form>")]
pub async fn signing_registration(
	form: Form<SigningRegistrationMessage>,
	mut end: Shutdown,
	queue: &State<Sender<SigningMessage>>, //hack
	hackmap: &State<HashMap<usize, bool>>, //hack
) -> EventStream![] {
	// If there isn't yet a signing party corresponding to this SigningRegistration, register one,
	// and create a thread to manage it.
	//
	// temp hack: implement with a single managed channel (`queue`) first. Then worry about
	// registration/pool management.
	let msg = form.into_inner();
	let is_party_completed = hackmap.get(&msg.party_id).unwrap_or_else(||
		// create a new party, todo
		&false);
	assert!(!is_party_completed, "party_id {} already completed", msg.party_id);

	// let proc = tokio::spawn(|| { 	todo!() });

	// Pass all signing-protocol related messages to the registering subscriber.
	let mut rx = queue.subscribe();
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

/// Endpoint for other signing nodes to pass signing-protocol messages into.
/// Todo:
/// - Test: must fail if party is over
/// - Test: must not fail if messages are out of order
/// - Note: do we authenticate who sends message here or in tofn?
/// - Note: Eventually, going to need a pool of channels, not just one. Start with one managed
///   channel, then figure out how to manage a pool.
#[post("/signing_message", data = "<form>")]
pub fn signing_message(
	form: Form<SigningMessage>,
	channel: &State<Sender<SigningMessage>>, // <- hack, use a managed pool
) {
	let _res = channel.send(form.into_inner());
}
