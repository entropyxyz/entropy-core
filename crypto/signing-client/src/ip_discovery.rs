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

use crate::{
	errors::{CustomIPError, SigningProtocolError},
	signer::{InitPartyInfo, ProtocolManager, SubscriberManager},
	Global, SIGNING_PARTY_SIZE,
};
use futures::TryFutureExt;
use reqwest::{self};
use rocket::{http::Status, serde::json::Json, State};
use tracing::instrument;
use uuid::Uuid;

/// Collect IPs for all signers then informs them
#[instrument]
#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(ip_address: String, global: &State<Global>) -> Result<Status, CustomIPError> {
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	// TODO JA validate not a duplicated IP
	info!("get_ip");
	let global = global.inner();
	let init_party_info = {
		let ip_addresses = &mut *global.current_ips.lock().unwrap();
		if ip_addresses.contains(&ip_address) {
			return Err(CustomIPError::new("Duplicate IP"))
		} else if ip_addresses.len() < SIGNING_PARTY_SIZE {
			ip_addresses.push(ip_address);
			return Ok(Status::Ok)
		} else {
			// All IP addresses collected. Construct InitPartyInfo and notify nodes to proceed.
			ip_addresses.push(ip_address);
			let party_id = global.get_next_party_id();
			let sig_uid = None; // todo: look for prior signature uids
			let key_uid = Uuid::new_v4(); // todo: get key_uid
			let msg = "".into(); // todo: get message
			InitPartyInfo::new(party_id, ip_addresses.clone(), key_uid, msg, sig_uid)
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
	let sanitized_info = init_party_info.into_inner().sanitize().unwrap();
	let (finalized_subscribing_tx, protocol_manager) = ProtocolManager::new(sanitized_info);
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
	// Todo: Should I spawn a task?
	let _outcome = protocol_manager
		.subscribe_and_await_subscribers()
		.and_then(move |subscribed_party| subscribed_party.sign())
		.await
		.unwrap()
		.get_result()
		.as_ref()
		.unwrap(); // todo: better error handling

	Ok(Status::Ok)
}
