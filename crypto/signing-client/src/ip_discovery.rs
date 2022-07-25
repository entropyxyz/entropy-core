//! # IP Discovery
//!
//!
//! ## Overview
//!
//! This file acts to help nodes communicate so they can start the signing process
//! Communication manager will collect IPs for all signers then inform them they are signing
//!
//! ## Routes
//!
//! get_ip - get - Comm manager accepts sign request for a message
//! get_all_ips - post - Comm manager sends signers all node addresses to sign message
#![allow(unused_variables)]
#![allow(unused_imports)]
use std::{intrinsics::transmute, marker::PhantomData};

use crate::{
	errors::CustomIPError,
	signer::{SigningMessage, SubscribingMessage},
	Global, PartyId, RxChannel, SIGNING_PARTY_SIZE,
};
use futures::{future, TryFutureExt};
use reqwest::{self};
use rocket::{http::Status, response::stream::ByteStream, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::Sender;
use tracing::instrument;

/// Information passed from the Communication Manager to all nodes on SigningParty Initialization.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InitPartyInfo {
	pub party_id: PartyId,
	pub ip_addresses: Vec<String>,
}

impl InitPartyInfo {
	pub(crate) fn new(global: &Global, ip_addresses: Vec<String>) -> Self {
		let party_id = {
			let mut party_id = *global.party_id_nonce.lock().unwrap();
			party_id += 1;
			party_id
		};
		Self { party_id, ip_addresses }
	}
}

#[tylift::tylift(mod state)]
pub(crate) enum SigningState {
	Subscribing,
	Signing,
	Complete,
}

#[derive(Debug)]
pub struct SigningParty<State: state::SigningState> {
	/// The unique signing protocol nonce
	pub party_id: PartyId,
	/// An IP address for each other Node in the protocol
	pub ip_addresses: Vec<String>,
	/// A receiving channel from each other node in the protocol
	pub channels: Option<Vec<RxChannel>>,
	/// Size of the signing party
	pub signing_party_size: usize,
	/// Number of times this node has received subscriptions for this signing protocol. Upon
	/// receiving `signing_party_size', subscriptions, this node will proceed to signing.
	pub n_subscribers: usize,
	/// Outcome of the signing protocol
	pub result: Option<()>, // todo
	/// Parameterization state of signging protocol
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

/// Collect IPs for all signers then informs them
#[instrument]
#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(ip_address: String, global: &State<Global>) -> Result<Status, CustomIPError> {
	info!("get_ip");
	let global = global.inner();
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	// TODO JA validate not a duplicated IP
	// TODO(TK): rewrote this to use an arc and unlock only once. Still could have better flow.

	let init_party_info = {
		let current_ips_mutex = global.current_ips.clone();
		let ip_addresses = &mut *current_ips_mutex.lock().unwrap();
		if ip_addresses.contains(&ip_address) {
			return Err(CustomIPError::new("Duplicate IP"))
		// @JA: validate this line, updated from 4 to SPS=6
		} else if ip_addresses.len() < SIGNING_PARTY_SIZE {
			ip_addresses.push(ip_address);
			return Ok(Status::Ok)
		} else {
			// TODO(TK): clarify what this branch is doing
			ip_addresses.push(ip_address);
			let v = ip_addresses.to_vec();

			InitPartyInfo::new(global, ip_addresses.clone())
		}
	};

	for ip in &init_party_info.ip_addresses {
		let res = reqwest::Client::new()
			.post(format!("http://{}/new_party", ip))
			.header("Content-Type", "application/json")
			.json(&init_party_info)
			.send()
			.await
			.unwrap();
	}
	Ok(Status::Ok)
}

/// Initiate a new signing party.
/// Communication Manager calls this endpoint for each node in the new Signing Party.
///
/// Upon receiving `new_party`, this node contacts all other nodes in the party and initiates the
/// signing protocol.
#[instrument]
#[post("/new_party", format = "json", data = "<party_info>")]
pub async fn new_party(
	party_info: Json<InitPartyInfo>,
	_global: &State<Global>,
	// TODO(TK): make an Error type
) -> Result<Status, CustomIPError> {
	info!("new_party");
	let party = SigningParty::from(party_info.into_inner());

	tokio::spawn(async move {
		if let Err(e) = party
			.subscribe_and_await_subscribers()
			.and_then(move |party| party.sign())
			.await
		{
			// TODO(TK): handle errors
			todo!();
		}
	});
	Ok(Status::Ok)
}

impl SigningParty<state::Subscribing> {
	/// Subscribe: Call `subscribe` on each other node in the signing party. Get back vector of
	/// receivers.
	// #[instrument]
	async fn subscribe_and_await_subscribers(
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
		todo!()
	}
}

// impl SigningParty<state::Complete> {
// 	pub(crate) fn get_result(self) -> anyhow::Result<()> {
// 		Ok(())
// 	}
// }
