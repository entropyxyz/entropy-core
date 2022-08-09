use super::SigningMessage;
use crate::{PartyUid, SignerState, SIGNING_PARTY_SIZE};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SubscribingMessage {
	pub party_id: PartyUid,
}

/// A message sent by subscribing node. Holder struct for subscription-related methods.
impl SubscribingMessage {
	pub(crate) fn new(party_id: PartyUid) -> Self {
		Self { party_id }
	}

	// not clear what this should do yet
	pub(crate) fn validate_registration(&self) -> anyhow::Result<()> {
		Ok(())
	}

	/// Retreive the SubscriberManager for this party, update it with a new subscriber.
	pub(crate) fn create_new_subscription(
		&self,
		map: &mut HashMap<PartyUid, Option<SubscriberManager>>,
	) -> broadcast::Receiver<SigningMessage> {
		let mut subscriber_manager = map.remove(&self.party_id).unwrap().unwrap();
		let rx = subscriber_manager.new_subscriber();
		map.insert(self.party_id, Some(subscriber_manager));
		rx
	}

	/// Yield messages as events in a stream as they arrive. Helper for `subscribe`.
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
	/// Marked true when the count matches SIGNING_PARTY_SIZE
	pub done: bool,
	/// When count = party_size, this channel will pass a Ready message, containing the
	/// fully-subscribed broadcast sender.
	pub finalized_tx: Option<oneshot::Sender<broadcast::Sender<SigningMessage>>>,
	/// The broadcast tx, to send other nodes messages. Used to produce receiver channels in the
	/// Subscribing phase.
	pub broadcast_tx: Option<broadcast::Sender<SigningMessage>>,
}

impl SubscriberManager {
	pub(crate) fn new(finalized_tx: oneshot::Sender<broadcast::Sender<SigningMessage>>) -> Self {
		let (broadcast_tx, _) = broadcast::channel(1000);
		Self {
			count: 0,
			done: false,
			finalized_tx: Some(finalized_tx),
			broadcast_tx: Some(broadcast_tx),
		}
	}

	/// Update Self with a new subscriber.
	/// If this was the final subscriber, send broadcast_tx back to the ProtocolManager.
	fn new_subscriber(&mut self) -> broadcast::Receiver<SigningMessage> {
		assert!(!self.done);
		self.count += 1;
		let rx = self.broadcast_tx.as_ref().unwrap().subscribe();
		if self.count == SIGNING_PARTY_SIZE {
			self.done = true;
			let broadcast_tx = self.broadcast_tx.take().unwrap();
			let finalized_tx = self.finalized_tx.take().unwrap();
			let _ = finalized_tx.send(broadcast_tx);
		}
		rx
	}
}
