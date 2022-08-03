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
// use merge_streams::{IntoStream, MergeStreams, StreamExt as MergeStreamExt};
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
	pub rx_stream: Option<u64>, // todo: replace with stream
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

	// async fn subscribe_to_party<S: futures::stream::Stream<Item = Result<Bytes, std::io::Error>>>(&mut self) -> anyhow::Result<()> {
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
		let v = futures::stream::iter(responses);
		// map the responses to byte streams
		// This nopes the heck out: found an opaque return type.
		// let v_streams: Vec<S> = v.map(|response| response.bytes_stream()).collect().await;
		// let message_streams = message_streams.
		// let message_streams = message_streams
		// .map(|response| response.bytes_stream());
		// let mapped_response = message_streams.
		// let message_streams = responses
		// 	.into_iter()
		// 	.map(|response| {
		// 		// a filtered stream of responses
		// 		let stream: futures::stream::FilterMap<S, Fut, F> =
		// 			response.bytes_stream().filter_map(|bytes| async {
		// 				let b = &*bytes.unwrap();
		// 				let is_crap = b == b":\n" || b == b"\n";
		// 				if !is_crap {
		// 					Some(b)
		// 				// Some(Box::pin(SigningMessage::try_from(b).unwrap()))
		// 				// Some(SigningMessage::try_from(b).unwrap())
		// 				} else {
		// 					None
		// 				}
		// 			});
		// 		stream
		// 	})
		// 	.collect();

		// let merged = select_all(message_streams);
		// let merged = select_all(message_streams);
		// let stream: BoxStream<'static, SigningMessage> = Box::pin(merged);
		// self.rx_stream = Some(merged);

		// self.merged_rx_channels = Some(Self::merge_streams(message_streams)?);
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
