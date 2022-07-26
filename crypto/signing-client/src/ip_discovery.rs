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
	signer::{InitPartyInfo, SigningMessage, SigningParty, SubscribingMessage},
	Global, PartyId, RxChannel, SIGNING_PARTY_SIZE,
};
use futures::{future, TryFutureExt};
use reqwest::{self};
use rocket::{http::Status, response::stream::ByteStream, serde::json::Json, Shutdown, State};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::Sender;
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
///
/// Upon receiving `new_party`, this node contacts all other nodes in the party and initiates the
/// signing protocol.
#[instrument]
#[post("/new_party", format = "json", data = "<party_info>")]
pub async fn new_party(
	party_info: Json<InitPartyInfo>,
	_global: &State<Global>,
) -> Result<Status, SigningProtocolError> {
	info!("new_party");
	let party = SigningParty::from(party_info.into_inner());

	if let Err(e) = party
		.subscribe_and_await_subscribers()
		.and_then(move |party| party.sign())
		.await
	{
		// TODO(TK): handle errors
		return Err(SigningProtocolError::Other("we're very disappointed"))
	}

	Ok(Status::Ok)
}

/// An endpoint for other nodes to subscribe to messages produced by this node.
///
/// Todo:
/// - What if this node hasn't yet heard about the SigningParty?
/// - validate the IP address of the caller
/// - Test: must fail if party is over
// #[instrument]
#[post("/subscribe", data = "<subscribing_message>")]
pub async fn subscribe(
	subscribing_message: Json<SubscribingMessage>,
	end: Shutdown,
	state: &State<Global>,
) -> () {
	// ) -> EventStream![SigningMessage] {
	// info!("signing_registration");
	let subscribing_message = subscribing_message.into_inner();
	let state = state.inner();

	// validate that the CM has told this node about the signing party
	// and the ip address of the caller is valid
	if !subscribing_message.validate_registration(&state) {
		// TODO(TK): handle
	}

	// get the broadcast sender for the party, add a new subscriber, and increment subscriber count
	// let rx =

	// Subscribe to the sender, creating one if it doesn't yet exist.
	// let rx = subscribe_or_create_channel(cached_state, new_party.clone());
	todo!()
}
