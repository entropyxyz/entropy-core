use std::{intrinsics::transmute, marker::PhantomData};

use crate::{
	errors::CustomIPError,
	signer::{init_party_info::InitPartyInfo, SigningMessage, SubscribingMessage},
	Global, PartyId, SIGNING_PARTY_SIZE,
};
use futures::{future, Stream, StreamExt, TryFutureExt, channel::oneshot};
use merge_streams::{IntoStream, MergeStreams, StreamExt as MergeStreamExt};
use reqwest::{self};
use rocket::{
	http::{hyper::body::Bytes, Status},
	response::stream::ByteStream,
	serde::json::Json,
	State,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{self, Sender};
use tracing::instrument;

#[tylift::tylift(mod state)]
/// Type parameterization of the state of protocol execution
enum SigningState {
	Subscribing,
	Signing,
	Complete,
}

// #[derive(Debug)]
pub(crate) struct SigningParty<State: state::SigningState> {
	/// The unique signing protocol nonce
	party_id: PartyId,
	/// An IP address for each other Node in the protocol
	ip_addresses: Vec<String>,
	/// A receiving channel from each other node in the protocol
	// todo: this might be better as a single merged stream
	rx_channel: Option<MessageStream>,
	/// Size of the signing party
	signing_party_size: usize,
	/// the broadcasting sender for the party
	broadcast_channel: broadcast::Sender<SigningMessage>,
	/// Number of times this node has received subscriptions for this signing protocol. Upon
	/// receiving `signing_party_size', subscriptions, this node will proceed to signing.
	n_subscribers: usize,
	/// Outcome of the signing protocol
	result: Option<anyhow::Result<()>>, // todo
	/// Type parameterization of the state of protocol execution
	_marker: PhantomData<State>,
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

impl From<InitPartyInfo> for SigningParty<state::Subscribing> {
	fn from(info: InitPartyInfo) -> SigningParty<state::Subscribing> {
		let (tx, _) = broadcast::channel(1000); // effectively unbound
		SigningParty {
			party_id: info.party_id,
			ip_addresses: info.ip_addresses,
			rx_channel: None,
			signing_party_size: SIGNING_PARTY_SIZE,
			broadcast_channel: tx,
			n_subscribers: 0,
			result: None,
			_marker: PhantomData,
		}
	}
}

impl SigningParty<state::Subscribing> {
	/// Subscribe: Call `subscribe` on each other node in the signing party. Get back vector of
	/// receivers.
	// #[instrument]
	pub(crate) async fn subscribe_and_await_subscribers(
		mut self,
		subscriber_rx: oneshot::Receiver<()>,
	) -> anyhow::Result<SigningParty<state::Signing>> {
		// info!("subscribe_to_party");

		let mut handles = Vec::with_capacity(self.ip_addresses.len());

		for ip in self.ip_addresses.clone() {
			let client = reqwest::Client::new();
			handles.push(
				client
					.post(format!("http://{}/subscribe", ip))
					.header("Content-Type", "application/json")
					.json(&SubscribingMessage::new(self.party_id))
					.send(),
			);
		}

		let rx_channels: Vec<_> = future::join_all(handles)
			.await
			.into_iter()
			// ignore the crap
			.map(|x| {
				x.unwrap()
					.bytes_stream()
					.map(|x| x.unwrap())
					.filter(|x| future::ready(&**x != b":\n" && &**x != b"\n"))
			})
			.collect();

		// TODO(TK): actually merge these streams though
		// let rx_channel = rx_channels.merge().into_stream();
		// self.rx_channel = Some(rx_channel);
		self.rx_channel = None; // placeholder

		unsafe { Ok(transmute(self)) }
	}

	/// Add a new subscriber to this node's list of subscribees
	pub(crate) async fn new_subscriber(&mut self) -> broadcast::Receiver<SigningMessage> {
		self.n_subscribers += 1;
		self.broadcast_channel.subscribe()
	}
}

impl SigningParty<state::Signing> {
	pub(crate) async fn sign(mut self) -> anyhow::Result<SigningParty<state::Complete>> {
		self.result = Some(Ok(())); // todo
		unsafe { Ok(transmute(self)) }
	}
}

impl SigningParty<state::Complete> {
	pub(crate) fn get_result(&self) -> &anyhow::Result<()> {
		// unwrap is safe because of state parameterization
		self.result.as_ref().unwrap()
	}
}
