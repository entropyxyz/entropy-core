use std::{intrinsics::transmute, marker::PhantomData};

use crate::{subscriber::SubscribingMessage, PartyUid, SIGNING_PARTY_SIZE};
use futures::{future, stream::BoxStream, StreamExt};
use reqwest::{self};
use serde::{Deserialize, Serialize};
use shared_crypto::CMInfo;
use tokio::sync::{broadcast, oneshot};
use tracing::instrument;

// use super::context::PartyInfo;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, UriDisplayQuery))]
#[serde(crate = "rocket::serde")]
pub struct SigningMessage {
	pub party_id: PartyUid,
}

impl TryFrom<&[u8]> for SigningMessage {
	type Error = serde_json::Error;

	// There may be a better way to write this. The Reqwest Bytes response includes non-json
	// crap that needs to be handled before deserialization.
	fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
		serde_json::from_str(std::str::from_utf8(value).unwrap().trim().split_once(':').unwrap().1)
	}
}

pub(crate) struct ProtocolManager<T: state::ProtocolState> {
	/// Information about the party provided by the Communication Manager
	pub cm_info: CMInfo,
	/// Size of the signing party
	pub signing_party_size: usize,
	/// A channel for the `SubscriberManager` to indicate readiness for the Signing phase
	pub finalized_subscribing_rx: Option<oneshot::Receiver<broadcast::Sender<SigningMessage>>>,
	/// A merged stream of messages from all other nodes in the protocol
	// todo: validate that static isn't a memory leak, or fix it
	pub rx_stream: Option<BoxStream<'static, SigningMessage>>,
	/// The broadcasting sender for the party. `SubscriberUtil` holds onto it until all parties
	/// have subscribed.
	pub broadcast_tx: Option<broadcast::Sender<SigningMessage>>,
	/// Outcome of the signing protocol
	pub result: Option<anyhow::Result<()>>, // todo
	/// Type parameterization of the state of protocol execution
	_marker: PhantomData<T>,
}

/// Exclude rx_stream and Phantomdata.
impl<T: state::ProtocolState> std::fmt::Debug for ProtocolManager<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ProtocolManager")
			.field("cm_info", &self.cm_info)
			.field("signing_party_size", &self.signing_party_size)
			.field("finalized_subscribing_rx", &self.finalized_subscribing_rx)
			// .field("rx_stream", &self.rx_stream) // no way
			.field("broadcast_tx", &self.broadcast_tx)
			.field("result", &self.result)
			// .field("_marker", &self._marker) // don't do it
			.finish() // nice
	}
}

impl<T: state::ProtocolState> ProtocolManager<T> {
	pub fn new(cm_info: CMInfo) -> (oneshot::Sender<broadcast::Sender<SigningMessage>>, Self) {
		{
			let (finalized_subscribing_tx, finalized_subscribing_rx) = oneshot::channel();
			(
				finalized_subscribing_tx,
				Self {
					cm_info,
					signing_party_size: SIGNING_PARTY_SIZE,
					finalized_subscribing_rx: Some(finalized_subscribing_rx),
					rx_stream: None,
					broadcast_tx: None,
					result: None,
					_marker: PhantomData,
				},
			)
		}
	}
}

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

	/// Call `subscribe` on every other node with a reqwest client. Merge the streamed responses
	/// into a single stream.
	async fn subscribe_to_party(&mut self) -> anyhow::Result<()> {
		let handles: Vec<_> = self // Call subscribe on every other node
			.cm_info
			.ip_addresses
			.iter()
			.map(|ip| {
				reqwest::Client::new()
					.post(format!("http://{}/subscribe", ip))
					.header("Content-Type", "application/json")
					.json(&SubscribingMessage::new(self.cm_info.party_uid))
					.send()
			})
			.collect();
		let responses: Vec<reqwest::Response> = future::try_join_all(handles).await?;

		let streams: Vec<_> = responses // Filter the streams, map them to messages
			.into_iter()
			.map(|resp: reqwest::Response| {
				resp.bytes_stream().filter_map(|result| {
					let bytes = result.unwrap();
					info!("got bytes: {:?}", bytes);
					let msg = SigningMessage::try_from(&*bytes);
					info!("got msg: {:?}", msg);
					future::ready(msg.ok())
				})
			})
			.collect();
		// Merge the streams, pin-box them to handle the opaque types
		let stream: BoxStream<'static, SigningMessage> =
			Box::pin(futures::stream::select_all(streams));
		self.rx_stream = Some(stream);
		Ok(())
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

// beneath this line: todo
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
