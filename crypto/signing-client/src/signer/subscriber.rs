use super::SigningMessage;
use crate::{Global, PartyId, SIGNING_PARTY_SIZE};
use rocket::{
	response::stream::{Event, EventStream},
	serde::json::Json,
	Shutdown, State,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::{
	select,
	sync::{
		broadcast::{self, error::RecvError},
		oneshot,
	},
};
use tracing::instrument;

/// An endpoint for other nodes to subscribe to messages produced by this node.
///
/// Todo:
/// - What if this node hasn't yet heard about the `ProtocolManager`?
/// - validate the IP address of the caller
/// - Test: must fail if party is over
#[instrument]
#[post("/subscribe", data = "<subscribing_message>")]
pub async fn subscribe(
	subscribing_message: Json<SubscribingMessage>,
	#[allow(unused_mut)] // macro shenanigans fooling our trusty linter
	mut end: Shutdown,
	state: &State<Global>,
	// ) {
) -> EventStream![] {
	info!("signing_registration");
	if let Err(e) = subscribing_message.validate_registration() {
		// TODO(TK): handle validation, and the possibility that the communication manager hasn't
		// touched this node yet. Can I return a Result<EventStream>?
	}

	let subscribing_message = subscribing_message.into_inner();
	let mut subscriber_manager_map = state.inner().subscriber_manager_map.lock().unwrap();
	// KEEP until testing, also may use state for ^validate registration
	// let mut subscriber_manager_map = {
	// 	let state = state.inner();
	// 	state.subscriber_manager_map.lock().unwrap()
	// };

	let rx = subscribing_message.create_new_subscription(&mut subscriber_manager_map);
	// maybe unnecessary. Drop the subscriber map before returning to avoid blocking
	drop(subscriber_manager_map);
	subscribing_message.create_event_stream(rx, end)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SubscribingMessage {
	pub party_id: PartyId,
}

/// A message sent by subscribing node. Holder struct for subscription-related methods.
impl SubscribingMessage {
	pub(crate) fn new(party_id: PartyId) -> Self {
		Self { party_id }
	}

	/// Validate that the this node knows about party with `party_id`
	// todo:
	// and that the calling node is in the party group
	// pub(crate) fn validate_registration(&self, state: &GlobalHangshMap<>d, mut screHashMap<>d,
	// SubscriberManager
	pub(crate) fn validate_registration(&self) -> anyhow::Result<()> {
		// 	let channels = state.signing_channels.clone();
		// 	let contains_key = channels.lock().unwrap().contains_key(&self.party_id);
		// 	if contains_key {
		// 		true
		// 	} else {
		// 		false
		// 	}
		Ok(())
	}

	// retrieve the subscriber_manager from state to issue a new receiver channel
	pub(crate) fn create_new_subscription(
		&self,
		map: &mut HashMap<PartyId, Option<SubscriberManager>>,
	) -> broadcast::Receiver<SigningMessage> {
		let mut subscriber_manager = map.remove(&self.party_id).unwrap().unwrap();
		let rx = subscriber_manager.new_subscriber();
		map.insert(self.party_id, Some(subscriber_manager));
		rx
	}

	pub(crate) fn create_event_stream(
		&self,
		mut rx: broadcast::Receiver<SigningMessage>,
		mut end: Shutdown,
	) -> EventStream![] {
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
}

/// The number of subscribers, and a channel to indicate readiness
#[derive(Debug)]
pub(crate) struct SubscriberManager {
	/// How many other nodes have subscribed to this node
	pub count: usize,
	/// When count = party_size, this channel will pass a Ready message, containing the
	/// fully-subscribed broadcast sender.
	pub finalized_tx: Option<oneshot::Sender<broadcast::Sender<SigningMessage>>>,
	// The broadcast tx, to send other nodes messages. Used to produce receiver channels in the
	// Subscribing phase.
	pub broadcast_tx: Option<broadcast::Sender<SigningMessage>>,
}

impl SubscriberManager {
	pub(crate) fn new(finalized_tx: oneshot::Sender<broadcast::Sender<SigningMessage>>) -> Self {
		let (broadcast_tx, _) = broadcast::channel(1000);
		Self { count: 0, finalized_tx: Some(finalized_tx), broadcast_tx: Some(broadcast_tx) }
	}

	// If this was the final subscriber, send broadcast_tx back to the ProtocolManager, consuming
	// self. The API caller is responsible for returning ownership of SubscriberUtil to their
	// client.
	pub(crate) fn new_subscriber(&mut self) -> broadcast::Receiver<SigningMessage> {
		self.count += 1;
		let rx = self.broadcast_tx.as_ref().unwrap().subscribe();
		if self.count == SIGNING_PARTY_SIZE {
			let broadcast_tx = self.broadcast_tx.take().unwrap();
			let finalized_tx = self.finalized_tx.take().unwrap();
			let _ = finalized_tx.send(broadcast_tx);
		}
		rx
	}
}
