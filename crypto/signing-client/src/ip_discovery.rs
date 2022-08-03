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
	errors::{CustomIPError, SigningProtocolError},
	signer::{
		InitPartyInfo, ProtocolManager, SigningMessage, SubscriberManager, SubscribingMessage,
	},
	Global, PartyId, SIGNING_PARTY_SIZE,
};
use futures::{future, TryFutureExt};
use reqwest::{self};
use rocket::{
	http::Status,
	response::stream::{ByteStream, Event, EventStream},
	serde::json::Json,
	Shutdown, State,
};
use serde::{Deserialize, Serialize};
use tokio::{
	select,
	sync::{
		broadcast::{self, error::RecvError, Sender},
		oneshot,
	},
};
use tracing::instrument;

/// Collect IPs for all signers then informs them
// #[instrument]
#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(ip_address: String, global: &State<Global>) -> Result<Status, CustomIPError> {
	// info!("get_ip");
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

	let client = reqwest::Client::new();
	for ip in &init_party_info.ip_addresses {
		let res = client
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
/// The node creates a `ProtocolManager` to run the protocol, and a SubscriberManager to manage
/// subscribed nodes. This method should run the protocol, returning the result.
#[instrument]
#[post("/new_party", format = "json", data = "<init_party_info>")]
pub async fn new_party(
	init_party_info: Json<InitPartyInfo>,
	global: &State<Global>,
) -> Result<Status, SigningProtocolError> {
	info!("new_party");
	let state = global.inner();
	let (finalized_subscribing_tx, protocol_manager) =
		ProtocolManager::new(init_party_info.into_inner());
	let subscriber_manager = SubscriberManager::new(finalized_subscribing_tx);

	{
		// store subscriber manager in state, first checking that the party_id is new
		let map = &mut *state.subscriber_manager_map.lock().unwrap();
		if map.contains_key(&protocol_manager.party_id) {
			return Err(SigningProtocolError::Other("party id already exists"))
		}
		map.insert(protocol_manager.party_id, Some(subscriber_manager));
	}

	// Run the protocol.
	let complete_protocol = protocol_manager
		.subscribe_and_await_subscribers()
		.and_then(move |subscribed_party| subscribed_party.sign())
		.await;

	// TODO(TK): handle errors better
	match complete_protocol {
		Err(e) => Err(SigningProtocolError::Other("we're very disappointed")),
		Ok(protocol_result) => match protocol_result.get_result() {
			Ok(()) => Ok(Status::Ok),
			Err(e) => Err(SigningProtocolError::Other("we're very disappointed")),
		},
	}
}
