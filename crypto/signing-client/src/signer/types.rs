use std::{intrinsics::transmute, marker::PhantomData};

use crate::{
	errors::CustomIPError,
	signer::{init_party_info::InitPartyInfo, SigningMessage, SubscribingMessage},
	Global, PartyId, RxChannel, SIGNING_PARTY_SIZE,
};
use futures::{future, TryFutureExt};
use reqwest::{self};
use rocket::{http::Status, response::stream::ByteStream, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::Sender;
use tracing::instrument;

#[tylift::tylift(mod state)]
/// Type parameterization of the state of protocol execution
enum SigningState {
	Subscribing,
	Signing,
	Complete,
}

#[derive(Debug)]
pub(crate) struct SigningParty<State: state::SigningState> {
	/// The unique signing protocol nonce
	party_id: PartyId,
	/// An IP address for each other Node in the protocol
	ip_addresses: Vec<String>,
	/// A receiving channel from each other node in the protocol
	channels: Option<Vec<RxChannel>>,
	/// Size of the signing party
	signing_party_size: usize,
	/// Number of times this node has received subscriptions for this signing protocol. Upon
	/// receiving `signing_party_size', subscriptions, this node will proceed to signing.
	n_subscribers: usize,
	/// Outcome of the signing protocol
	result: Option<anyhow::Result<()>>, // todo
	/// Type parameterization of the state of protocol execution
	_marker: PhantomData<State>,
}

impl From<InitPartyInfo> for SigningParty<state::Subscribing> {
	fn from(info: InitPartyInfo) -> SigningParty<state::Subscribing> {
		SigningParty {
			party_id: info.party_id,
			ip_addresses: info.ip_addresses,
			channels: None,
			signing_party_size: SIGNING_PARTY_SIZE,
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
	) -> anyhow::Result<SigningParty<state::Signing>> {
		// info!("subscribe_to_party");
		let mut handles = Vec::with_capacity(self.ip_addresses.len());
		let client = reqwest::Client::new();
		for ip in &self.ip_addresses {
			handles.push(tokio::spawn(
				client
					.post(format!("http://{}/subscribe", ip))
					.header("Content-Type", "application/json")
					.json(&SubscribingMessage::new(self.party_id))
					.send(),
			))
		}
		// let v: Vec<ByteStream<Vec<u8>>> = future::join_all(handles)
		// 	.await
		// 	.into_iter()
		// 	.map(|res| {
		// 		let a: Result<Result<reqwest::Response, reqwest::Error>, tokio::task::JoinError> = res;
		// 		match res {
		// 			Err(e) => todo!(), // handle tokio error
		// 			Ok(res) => match res {
		// 				// handle response error
		// 				Err(e) => todo!(),
		// 				// response is a bytes stream from another node.
		// 				Ok(res) => ByteStream(res.bytes_stream()),
		// 			},
		// 		}
		// 	})
		// .collect();

		// future::join_all(handles).await.into_iter().map(|res| res.unwrap().unwrap()).collect()
		unsafe { Ok(transmute(self)) }
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
