use std::{intrinsics::transmute, marker::PhantomData};

use crate::{
	errors::CustomIPError,
	signer::{init_party_info::InitPartyInfo, SigningMessage, SubscribingMessage},
	Global, PartyId, SIGNING_PARTY_SIZE,
};
use futures::{future, Stream, StreamExt, TryFutureExt};
use merge_streams::{IntoStream, MergeStreams, StreamExt as MergeStreamExt};
use reqwest::{self};
use rocket::{
	http::{hyper::body::Bytes, Status},
	response::stream::{ByteStream, EventStream},
	serde::json::Json,
	State,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{
	broadcast::{self, Sender},
	mpsc, oneshot,
};
use tracing::instrument;

use super::context::PartyInfo;

#[tylift::tylift(mod state)]
/// Type parameterization of the state of protocol execution
enum ProtocolState {
	#[derive(Debug)]
	Subscribing,
	#[derive(Debug)]
	Signing,
	#[derive(Debug)]
	Complete,
}

#[derive(Debug)]
pub(crate) struct ProtocolManager<T: state::ProtocolState> {
	/// The unique signing protocol nonce
	pub party_id: PartyId,
	/// An IP address for each other Node in the protocol
	pub ip_addresses: Vec<String>,
	/// Size of the signing party
	pub signing_party_size: usize,
	/// A channel for the `SubscriberManager` to indicate readiness for the Signing phase
	pub finalized_subscribing_rx: Option<oneshot::Receiver<broadcast::Sender<SigningMessage>>>,
	// A receiving channel from each other node in the protocol
	// todo: this might be better as a single merged stream
	pub merged_rx_channels: Option<EventStreamWrapper>,
	/// the broadcasting sender for the party. `SubscriberUtil` holds onto it until all parties
	/// have subscribed.
	pub broadcast_tx: Option<broadcast::Sender<SigningMessage>>,
	// / Number of times this node has received subscriptions for this signing protocol. Upon
	// / receiving `signing_party_size', subscriptions, this node will proceed to signing.
	// pub n_subscribers: usize,
	/// Outcome of the signing protocol
	pub result: Option<anyhow::Result<()>>, // todo
	/// Type parameterization of the state of protocol execution
	_marker: PhantomData<T>,
}

/// A wrapper to around EventStream implementing Debug
pub struct EventStreamWrapper(EventStream<SigningMessage>);
impl std::fmt::Debug for EventStreamWrapper {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// f.debug_tuple("EventStreamWrapper").field(&self.0).finish()
		f.debug_tuple("EventStreamWrapper").finish()
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
	pub(crate) fn new(
		finalized_tx: oneshot::Sender<broadcast::Sender<SigningMessage>>,
		// broadcast_tx: broadcast::Sender<SigningMessage>,
	) -> Self {
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

// TODO(TK): hack, while I figure out what to type this stream
pub(crate) struct MessageStream;
impl Stream for MessageStream {
	type Item = Result<Bytes, reqwest::Error>;

	fn poll_next(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<Self::Item>> {
		todo!()
	}
}

impl<T: state::ProtocolState> ProtocolManager<T> {
	pub fn new(
		init_party_info: InitPartyInfo,
	) -> (oneshot::Sender<broadcast::Sender<SigningMessage>>, Self) {
		{
			let (finalized_subscribing_tx, finalized_subscribing_rx) = oneshot::channel();
			(
				finalized_subscribing_tx,
				Self {
					party_id: init_party_info.party_id,
					ip_addresses: init_party_info.ip_addresses,
					signing_party_size: SIGNING_PARTY_SIZE,
					finalized_subscribing_rx: Some(finalized_subscribing_rx),
					merged_rx_channels: None,
					broadcast_tx: None,
					result: None,
					_marker: PhantomData,
				},
			)
		}
	}
}

// todo: move this to own lib
impl ProtocolManager<state::Subscribing> {
	/// Subscribe: Call `subscribe` on each other node in the signing party. Get back vector of
	/// receiver streams. Then advance the protocol to the signing phase.
	#[instrument]
	pub(crate) async fn subscribe_and_await_subscribers(
		mut self,
		// subscribed_oneshot_rx: oneshot::Receiver<broadcast::Sender<SigningMessage>>,
	) -> anyhow::Result<ProtocolManager<state::Signing>> {
		info!("subscribe_and_await_subscribers");
		self.subscribe_to_party().await?;
		self.await_subscribers().await?;

		unsafe { Ok(transmute(self)) }
	}

	async fn subscribe_to_party(&mut self) -> anyhow::Result<()> {
		let mut handles = Vec::with_capacity(self.ip_addresses.len());
		for ip in &self.ip_addresses {
			let client = reqwest::Client::new();
			handles.push(
				client
					.post(format!("http://{}/subscribe", ip))
					.header("Content-Type", "application/json")
					.json(&SubscribingMessage::new(self.party_id))
					.send(),
			);
		}

		let responses: Vec<reqwest::Response> = future::try_join_all(handles).await?;
		// let message_streams = responses.into_iter().map(|response| {
		// 	response.bytes_stream().filter_map(|bytes| async {
		// 		let b = bytes.unwrap();
		// 		let is_crap = &*b == b":\n" || &*b == b"\n";
		// 		if is_crap {
		// 			// Some(Box::new(SigningMessage::try_from(b).unwrap()))
		// 			Some(SigningMessage::try_from(b).unwrap())
		// 		} else {
		// 			None
		// 		}
		// 	})
		// });
		let message_streams = futures::stream::iter(responses).map(|response| async {
			response.bytes_stream().filter_map(|bytes| async {
				let b = bytes.unwrap();
				let is_crap = &*b == b":\n" || &*b == b"\n";
				if is_crap {
					// Some(Box::new(SigningMessage::try_from(b).unwrap()))
					Some(SigningMessage::try_from(b).unwrap())
				} else {
					None
				}
			})
		});

		self.merged_rx_channels = Some(EventStreamWrapper(message_streams.flatten()));

		// self.merged_rx_channels = Some(Self::merge_streams(message_streams)?);
		Ok(())
	}

	fn merge_streams(
		streams: impl Iterator<Item = impl Stream<Item = SigningMessage>>,
	) -> anyhow::Result<EventStreamWrapper> {
		use merge_streams::MergeStreams;
		// let merged_stream = streams.merge(); // nope: trait bounds not satisfied.
		// let merged_stream = streams.collect().merge(); // nope: don't know what to collect into
		let merged_stream = streams.collect::<Vec<EventStream<SigningMessage>>>().merge(); // nope: can't build an eventstream
		Ok(EventStreamWrapper(merged_stream))
		// todo!();
	}

	/// Wait for other nodes to finish subscribing to this node. SubscriberManager sends a broadcast
	/// channel when all other nodes have subscribed.
	async fn await_subscribers(&mut self) -> anyhow::Result<()> {
		let rx = self.finalized_subscribing_rx.take().unwrap();
		let tx = rx.await?;
		self.broadcast_tx = Some(tx);
		Ok(())
	}
}

impl ProtocolManager<state::Signing> {
	pub(crate) async fn sign(mut self) -> anyhow::Result<ProtocolManager<state::Complete>> {
		self.result = Some(Ok(())); // todo
		unsafe { Ok(transmute(self)) }
	}
}

impl ProtocolManager<state::Complete> {
	pub(crate) fn get_result(&self) -> &anyhow::Result<()> {
		// unwrap is safe because of state parameterization
		self.result.as_ref().unwrap()
	}
}
