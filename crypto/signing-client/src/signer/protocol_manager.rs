use std::{intrinsics::transmute, marker::PhantomData, pin::Pin};

use crate::{
	errors::CustomIPError,
	signer::{init_party_info::InitPartyInfo, SigningMessage, SubscribingMessage},
	Global, PartyId, SIGNING_PARTY_SIZE,
};
use futures::{
	future,
	stream::{select_all, BoxStream},
	Stream, StreamExt, TryFutureExt,
};
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

// #[derive(Debug)]
pub(crate) struct ProtocolManager<T: state::ProtocolState> {
	/// The unique signing protocol nonce
	pub party_id: PartyId,
	/// An IP address for each other Node in the protocol
	pub ip_addresses: Vec<String>,
	/// Size of the signing party
	pub signing_party_size: usize,
	/// A channel for the `SubscriberManager` to indicate readiness for the Signing phase
	pub finalized_subscribing_rx: Option<oneshot::Receiver<broadcast::Sender<SigningMessage>>>,
	// A merged stream of messages from all other nodes in the protocol
	pub rx_stream: Option<BoxStream<'static, SigningMessage>>,
	/// the broadcasting sender for the party. `SubscriberUtil` holds onto it until all parties
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
			.field("party_id", &self.party_id)
			.field("ip_addresses", &self.ip_addresses)
			.field("signing_party_size", &self.signing_party_size)
			.field("finalized_subscribing_rx", &self.finalized_subscribing_rx)
			// .field("rx_stream", &self.rx_stream)
			.field("broadcast_tx", &self.broadcast_tx)
			.field("result", &self.result)
			// .field("_marker", &self._marker)
			.finish()
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

	// async fn subscribe_to_party<S: futures::stream::Stream<Item = Result<Bytes,
	// std::io::Error>>>(&mut self) -> anyhow::Result<()> {
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

		// let message_streams: Vec<Pin<Box<dyn Stream<Item = SigningMessage>>>> = responses

		// get an iterator of the responses
		// let v = responses.into_iter().map(|resp: reqwest::Response|
		// resp.bytes_stream()).collect();

		// this actually works fine, with Bytes.
		let streams: Vec<_> = responses
			.into_iter()
			.map(|resp: reqwest::Response| {
				// filter map no-go
				// resp.bytes_stream().filter_map(|result| {
				// 	let bytes = result.unwrap();
				// 	SigningMessage::try_from(&*bytes).ok()
				// })
				resp.bytes_stream().filter_map(|result| {
					let bytes = result.unwrap();
					info!("got bytes: {:?}", bytes);
					let msg = SigningMessage::try_from(&*bytes);
					info!("got msg: {:?}", msg);
					future::ready(msg.ok())
				})
			})
			.collect();
		let stream = futures::stream::select_all(streams);
		let boxed_stream: BoxStream<'static, SigningMessage> = Box::pin(stream);
		self.rx_stream = Some(boxed_stream);

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
